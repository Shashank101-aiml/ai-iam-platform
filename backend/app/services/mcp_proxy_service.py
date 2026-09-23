"""
MCP Proxy Service — intercepts every tool call before execution.

This is what makes the platform genuinely useful in production:
instead of just recording THAT an agent called a tool, we intercept
BEFORE the call and can block it based on policy.

Flow:
  Agent → our proxy → resolve binding → OPA policy check → tool_filter
                   ↘ blocked at any step → audit log (committed immediately)
                   ↘ allowed → MCP server (circuit-breaker + size/time bounded)

Security properties:
1. mcp_server_url is resolved server-side from the agent's own
   mcp_bindings, never taken from the caller — closes an SSRF where an
   agent could otherwise point the proxy at an arbitrary address.
2. tool_filter enforces a per-binding tool allowlist even when a scope
   and OPA policy would otherwise allow the call — defense in depth.
3. Policy enforcement BEFORE execution — not logging after the fact.
4. Args are hashed, not stored (may contain secrets).
5. Results are hashed, not stored (may contain sensitive data).
6. Every call linked to the agent's causal trace for full reconstruction.
7. A blocked/failed call's session + audit rows are committed immediately,
   not left for the caller to commit — the request handler raises an
   HTTPException right after, and a session that rolls back on an
   uncaught exception (see app.db.session.get_db) would otherwise erase
   the very calls most worth keeping a record of.
8. Response size cap, timeout, and a per-server circuit breaker bound the
   blast radius of a slow, wedged, or malicious downstream MCP server.
9. Provenance-aware authorization: a per-binding untrusted_source flag
   (operator-authored, never agent-supplied) tags whether a call's
   result came from a source this platform doesn't control. If ANY
   earlier call in the same causal_trace_id was tainted this way, a
   LATER call in that trace attempting a high-risk capability
   (external_send, credential_access — also operator-authored, per
   tool) is denied by OPA outright, independent of scope. This is a
   heuristic against "read untrusted content, get instructions
   injected, exfiltrate" — not a claim to have solved prompt injection.
"""

import uuid
import time
import json
import hashlib
from typing import NamedTuple, Optional, Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException

from app.core.config import settings
from app.core.metrics import MCP_TOOL_DENIALS_TOTAL
from app.models.mcp_session import McpSession
from app.core.constants import AuditAction
from app.core.permissions import (
    check_permission,
    PermissionDeniedError,
    REASON_PROVENANCE,
    REASON_POLICY_UNAVAILABLE,
)
from app.repositories.audit_repo import audit_repo
from app.repositories.agent_repo import agent_repo
from app.repositories.mcp_session_repo import mcp_session_repo


class _ResolvedBinding(NamedTuple):
    """Everything resolved server-side from an agent's own mcp_bindings entry."""
    server_url: Optional[str]
    tool_filter: Optional[list[str]]
    untrusted_source: bool
    tool_capabilities: dict[str, list[str]]
    error: Optional[str]


# Human-readable text for authz.rego's deny_reasons codes. Presentation
# only — the decision itself was already made by OPA.
_DENY_REASON_TEXT = {
    "scope_not_granted": "the token does not carry the tool:execute scope",
    "blocked_tool": "the tool is on the policy's always-blocked list",
    "delegation_depth_exceeded": "the delegation depth exceeds the policy ceiling",
    "malformed_input": "the request did not identify its agent and org",
}


def _classify_policy_denial(
    err: PermissionDeniedError, tool_name: str, capabilities: list[str]
) -> tuple[str, str]:
    """
    Turn an OPA denial into (policy_decision, reason).

    policy_decision is what the dashboard, the audit trail and the
    aiiam_mcp_tool_denials_total metric group by, so each distinct cause
    gets its own value rather than one catch-all: a provenance denial (an
    earlier call in this trace retrieved untrusted content) and an OPA
    outage that failed closed are both operationally very different from
    an ordinary scope/blocked-tool denial.
    """
    base = str(err)
    reasons = err.reasons

    if REASON_POLICY_UNAVAILABLE in reasons:
        return "policy_unavailable", f"{base} — the policy engine could not be reached, so the call failed closed"

    if reasons == [REASON_PROVENANCE]:
        caps = ", ".join(capabilities) if capabilities else "a high-risk capability"
        return (
            "provenance_denied",
            f"{base} — provenance: an earlier call in this trace retrieved untrusted content, "
            f"and '{tool_name}' is tagged {caps}",
        )

    if reasons:
        parts = []
        for code in reasons:
            if code == REASON_PROVENANCE:
                parts.append("an earlier call in this trace retrieved untrusted content and this tool is high-risk")
            else:
                parts.append(_DENY_REASON_TEXT.get(code, code))
        return "policy_denied", f"{base} — {'; '.join(parts)}"

    return "policy_denied", base


def _hash_payload(data: Any) -> str:
    """SHA256 hash of a JSON-serializable payload."""
    serialized = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode()).hexdigest()


def _safe_args_metadata(args: dict) -> dict:
    """
    Extract non-sensitive metadata from tool args.
    Never stores values — only structural info.
    """
    return {
        "arg_count": len(args),
        "arg_keys": list(args.keys()),     # Key names are generally safe
        "has_nested": any(isinstance(v, (dict, list)) for v in args.values()),
    }


class _CircuitBreaker:
    """
    Per-MCP-server circuit breaker, in-process only.

    Once MCP_CIRCUIT_BREAKER_FAILURE_THRESHOLD consecutive calls to the
    same server fail, further calls are short-circuited (no network call
    at all) for MCP_CIRCUIT_BREAKER_COOLDOWN_SECONDS, so one wedged
    downstream server can't tie up the proxy's connections with calls
    that were always going to time out.

    In-memory only — state isn't shared across worker processes or
    replicas. Good enough for a single-instance deployment; a
    multi-replica deployment would need this in Redis instead.
    """

    def __init__(self):
        self._failures: dict[str, int] = {}
        self._opened_at: dict[str, float] = {}

    def is_open(self, server_id: str) -> bool:
        opened_at = self._opened_at.get(server_id)
        if opened_at is None:
            return False
        if time.monotonic() - opened_at >= settings.MCP_CIRCUIT_BREAKER_COOLDOWN_SECONDS:
            # Cooldown elapsed — let one trial call through (half-open).
            self._opened_at.pop(server_id, None)
            self._failures[server_id] = 0
            return False
        return True

    def record_success(self, server_id: str) -> None:
        self._failures[server_id] = 0
        self._opened_at.pop(server_id, None)

    def record_failure(self, server_id: str) -> None:
        count = self._failures.get(server_id, 0) + 1
        self._failures[server_id] = count
        if count >= settings.MCP_CIRCUIT_BREAKER_FAILURE_THRESHOLD:
            self._opened_at[server_id] = time.monotonic()


_circuit_breaker = _CircuitBreaker()


class McpProxyService:

    async def execute_tool(
        self,
        db: AsyncSession,
        *,
        agent_id: str,
        org_id: str,
        mcp_server_id: str,
        tool_name: str,
        tool_args: dict,
        token_scopes: list[str],
        causal_trace_id: str,
        delegation_depth: int = 0,
        source_ip: Optional[str] = None,
        token_resource: Optional[str] = None,
        authorization_details: Optional[list[dict]] = None,
    ) -> dict:
        """
        Proxy a tool call through binding resolution and policy enforcement.

        Steps:
        1. Resolve mcp_server_url + tool_filter + provenance metadata
           from the agent's own mcp_bindings (never from the caller —
           SSRF prevention)
        2. RFC 8707 Resource Indicator enforcement (token_resource, if set)
        3. RFC 9396 task-scope enforcement (authorization_details, if set)
        4. Resolve this trace's provenance taint + this call's risk
           capabilities, then OPA policy check (fail closed) — denies a
           high-risk capability outright if an earlier call in the SAME
           trace already pulled untrusted content
        5. tool_filter enforcement
        6. If allowed: forward to MCP server (circuit-breaker + size/time bounded)
        7. Record session with hashed args/results (+ this call's own
           source_untrusted tag, for the NEXT call in the trace to see)
        8. Emit audit event
        9. Return result to agent
        """
        session_id = str(uuid.uuid4())
        args_hash = _hash_payload(tool_args)
        args_metadata = _safe_args_metadata(tool_args)
        start_time = time.monotonic()

        # Step 1: resolve the real server URL ourselves — the request
        # body never carries one.
        binding = await self._resolve_mcp_binding(
            db, agent_id=agent_id, org_id=org_id, mcp_server_id=mcp_server_id
        )
        if binding.error is not None:
            await self._block(
                db,
                session_id=session_id,
                org_id=org_id,
                agent_id=agent_id,
                mcp_server_id=mcp_server_id,
                mcp_server_url=f"unresolved:{mcp_server_id}",
                tool_name=tool_name,
                args_hash=args_hash,
                args_metadata=args_metadata,
                causal_trace_id=causal_trace_id,
                reason=binding.error,
                source_ip=source_ip,
                policy_decision="binding_denied",
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "tool_call_blocked",
                    "tool": tool_name,
                    "reason": binding.error,
                    "session_id": session_id,
                },
            )
        server_url, tool_filter = binding.server_url, binding.tool_filter

        # Step 2: RFC 8707 Resource Indicator enforcement — a token
        # minted bound to ONE specific mcp_server_id (via the OAuth
        # authorization_code flow's resource= parameter — see
        # api/oauth.py and core/jwt.py's create_agent_access_token)
        # must never work against any OTHER server, even one the agent
        # is separately bound to and even though scopes/OPA would
        # otherwise allow it. token_resource is None for tokens from
        # the legacy /token/exchange path — unchanged, scope-only
        # behavior for those.
        if token_resource is not None and token_resource != mcp_server_id:
            reason = (
                f"token is bound to resource '{token_resource}' "
                f"(RFC 8707 Resource Indicators), not '{mcp_server_id}'"
            )
            await self._block(
                db,
                session_id=session_id,
                org_id=org_id,
                agent_id=agent_id,
                mcp_server_id=mcp_server_id,
                mcp_server_url=server_url,
                tool_name=tool_name,
                args_hash=args_hash,
                args_metadata=args_metadata,
                causal_trace_id=causal_trace_id,
                reason=reason,
                source_ip=source_ip,
                policy_decision="resource_denied",
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "tool_call_blocked",
                    "tool": tool_name,
                    "reason": reason,
                    "session_id": session_id,
                },
            )

        # Step 3: RFC 9396 task-scope enforcement — a token minted bound
        # to specific (mcp_server_id, tool_name) pairs (via /token
        # /exchange's or /oauth/token's `intent`/task-scoping — see
        # core/jwt.py's authorization_details claim) must match the
        # EXACT call being made, not just an allowed server or a valid
        # scope. This is what closes the "ambient authority" gap: a
        # session-scoped bearer token can otherwise be replayed against
        # any tool call its scopes cover for its whole lifetime. A
        # mismatch here is a DISTINCT failure mode from a policy denial
        # — a different error code and a different policy_decision
        # value on the session row, both queryable/meterable
        # separately from a generic OPA/tool_filter block — because the
        # cause is completely different: the token simply was never
        # authorized for this call, independent of whether policy would
        # have allowed it.
        if authorization_details is not None:
            authorized = any(
                entry.get("mcp_server_id") == mcp_server_id and entry.get("tool_name") == tool_name
                for entry in authorization_details
            )
            if not authorized:
                reason = (
                    f"token is task-scoped (RFC 9396 authorization_details) to a "
                    f"different call; not authorized for tool '{tool_name}' on "
                    f"server '{mcp_server_id}'"
                )
                await self._block(
                    db,
                    session_id=session_id,
                    org_id=org_id,
                    agent_id=agent_id,
                    mcp_server_id=mcp_server_id,
                    mcp_server_url=server_url,
                    tool_name=tool_name,
                    args_hash=args_hash,
                    args_metadata=args_metadata,
                    causal_trace_id=causal_trace_id,
                    reason=reason,
                    source_ip=source_ip,
                    policy_decision="task_scope_denied",
                )
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "token_not_authorized_for_action",
                        "tool": tool_name,
                        "reason": reason,
                        "session_id": session_id,
                    },
                )

        # Step 4: resolve this trace's provenance taint (did an earlier
        # call in this SAME causal_trace_id already pull content from a
        # source this platform doesn't control?) and this call's own
        # risk capabilities, then run policy — OPA denies outright if a
        # high-risk capability (external_send, credential_access) is
        # attempted inside a tainted trace, regardless of scope/depth.
        provenance_tainted = await self._trace_is_tainted(
            db, causal_trace_id=causal_trace_id, org_id=org_id
        )
        capabilities = binding.tool_capabilities.get(tool_name, [])
        try:
            await check_permission(
                agent_id=agent_id,
                org_id=org_id,
                action="tool:execute",
                resource_type="mcp_tool",
                resource_id=tool_name,
                token_scopes=token_scopes,
                delegation_depth=delegation_depth,
                capabilities=capabilities,
                provenance_tainted=provenance_tainted,
            )
        except PermissionDeniedError as e:
            policy_decision, reason = _classify_policy_denial(e, tool_name, capabilities)
            await self._block(
                db,
                session_id=session_id,
                org_id=org_id,
                agent_id=agent_id,
                mcp_server_id=mcp_server_id,
                mcp_server_url=server_url,
                tool_name=tool_name,
                args_hash=args_hash,
                args_metadata=args_metadata,
                causal_trace_id=causal_trace_id,
                reason=reason,
                source_ip=source_ip,
                policy_decision=policy_decision,
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "tool_call_blocked",
                    "tool": tool_name,
                    "reason": reason,
                    "session_id": session_id,
                },
            )

        # Step 5: per-binding tool allowlist — defense in depth even if
        # scopes/OPA would otherwise allow this call.
        if tool_filter is not None and tool_name not in tool_filter:
            reason = f"tool '{tool_name}' is not in this binding's tool_filter"
            await self._block(
                db,
                session_id=session_id,
                org_id=org_id,
                agent_id=agent_id,
                mcp_server_id=mcp_server_id,
                mcp_server_url=server_url,
                tool_name=tool_name,
                args_hash=args_hash,
                args_metadata=args_metadata,
                causal_trace_id=causal_trace_id,
                reason=reason,
                source_ip=source_ip,
                policy_decision="tool_filter_denied",
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "tool_call_blocked",
                    "tool": tool_name,
                    "reason": reason,
                    "session_id": session_id,
                },
            )

        # Step 6: Forward to actual MCP server
        result, error_code = await self._call_mcp_server(
            server_url, mcp_server_id, tool_name, tool_args
        )
        duration_ms = int((time.monotonic() - start_time) * 1000)
        call_status = "success" if error_code is None else "error"
        result_hash = _hash_payload(result) if result is not None else None

        # Step 7: Record session with hashes only. source_untrusted only
        # ever True on an actual "success" — a call that errored never
        # retrieved content, so it can't have tainted anything, even if
        # its binding is itself marked untrusted_source.
        await self._record_session(
            db,
            session_id=session_id,
            org_id=org_id,
            agent_id=agent_id,
            mcp_server_id=mcp_server_id,
            mcp_server_url=server_url,
            tool_name=tool_name,
            args_hash=args_hash,
            args_metadata=args_metadata,
            result_hash=result_hash,
            status=call_status,
            source_untrusted=(binding.untrusted_source and call_status == "success"),
            policy_decision="allowed",
            blocking_reason=None,
            duration_ms=duration_ms,
            causal_trace_id=causal_trace_id,
            error_code=error_code,
        )

        # Step 8: Audit event
        await audit_repo.append(
            org_id=org_id,
            action=(
                AuditAction.MCP_TOOL_COMPLETED
                if call_status == "success"
                else AuditAction.MCP_TOOL_CALLED
            ),
            actor_type="agent",
            actor_id=agent_id,
            agent_id=agent_id,
            causal_trace_id=causal_trace_id,
            outcome=call_status,
            resource_type="mcp_tool",
            resource_id=tool_name,
            details={
                "mcp_server_id": mcp_server_id,
                "tool_name": tool_name,
                "args_hash": args_hash,
                "result_hash": result_hash,
                "duration_ms": duration_ms,
                "error_code": error_code,
            },
            source_ip=source_ip,
        )
        # Commit now — see module docstring point 7. The route also
        # commits on its own successful return, but this call is what
        # actually guarantees the row survives the 502 branch below.
        await db.commit()

        if error_code:
            raise HTTPException(
                status_code=502,
                detail={
                    "error": "mcp_tool_error",
                    "tool": tool_name,
                    "error_code": error_code,
                    "session_id": session_id,
                },
            )

        return {
            "session_id": session_id,
            "result": result,
            "duration_ms": duration_ms,
            "tool_name": tool_name,
        }

    async def _resolve_mcp_binding(
        self,
        db: AsyncSession,
        *,
        agent_id: str,
        org_id: str,
        mcp_server_id: str,
    ) -> _ResolvedBinding:
        """
        Resolve mcp_server_url + tool_filter + provenance metadata from
        the agent's OWN mcp_bindings — never from the caller's request
        body.

        .error is None on success; when set, the caller must treat this
        as blocked and every other field is meaningless.
        """
        agent = await agent_repo.get_by_id_and_org(db, agent_id, org_id)
        if agent is None:
            return _ResolvedBinding(None, None, False, {}, f"agent '{agent_id}' not found")

        for binding in (agent.mcp_bindings or []):
            if binding.get("server_id") == mcp_server_id:
                server_url = binding.get("server_url")
                if not server_url:
                    return _ResolvedBinding(
                        None, None, False, {},
                        f"mcp_server_id '{mcp_server_id}' binding has no server_url configured",
                    )
                return _ResolvedBinding(
                    server_url,
                    binding.get("tool_filter"),
                    bool(binding.get("untrusted_source", False)),
                    binding.get("tool_capabilities") or {},
                    None,
                )

        return _ResolvedBinding(
            None, None, False, {}, f"agent is not bound to mcp_server_id '{mcp_server_id}'"
        )

    async def _trace_is_tainted(
        self, db: AsyncSession, *, causal_trace_id: str, org_id: str
    ) -> bool:
        """
        True if any EARLIER, successfully-completed call in this same
        causal trace pulled content from a source this platform doesn't
        control (mcp_bindings[].untrusted_source). This is what makes
        the taint propagate FORWARD through a trace — a later call is
        judged by what the trace has already been exposed to, not just
        its own binding. A blocked or errored call never actually
        retrieved content, so only "success" rows count.
        """
        prior_sessions = await mcp_session_repo.get_by_trace(db, causal_trace_id, org_id)
        return any(s.source_untrusted and s.status == "success" for s in prior_sessions)

    async def _call_mcp_server(
        self,
        server_url: str,
        server_id: str,
        tool_name: str,
        args: dict,
    ) -> tuple[Optional[dict], Optional[str]]:
        """
        Forward the tool call to the actual MCP server.
        Returns (result, error_code). error_code is None on success.
        """
        if _circuit_breaker.is_open(server_id):
            return None, "mcp_circuit_open"

        try:
            async with httpx.AsyncClient(timeout=settings.MCP_CALL_TIMEOUT_SECONDS) as client:
                async with client.stream(
                    "POST",
                    f"{server_url}/tools/{tool_name}",
                    json={"arguments": args},
                    headers={"Content-Type": "application/json"},
                ) as response:
                    if response.status_code != 200:
                        await response.aread()
                        _circuit_breaker.record_failure(server_id)
                        return None, f"mcp_http_{response.status_code}"

                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body += chunk
                        if len(body) > settings.MCP_MAX_RESPONSE_BYTES:
                            _circuit_breaker.record_failure(server_id)
                            return None, "mcp_response_too_large"

            result = json.loads(bytes(body))
        except httpx.TimeoutException:
            _circuit_breaker.record_failure(server_id)
            return None, "mcp_timeout"
        except httpx.ConnectError:
            _circuit_breaker.record_failure(server_id)
            return None, "mcp_connection_refused"
        except json.JSONDecodeError:
            _circuit_breaker.record_failure(server_id)
            return None, "mcp_invalid_response"
        except Exception as e:
            _circuit_breaker.record_failure(server_id)
            return None, f"mcp_error:{type(e).__name__}"

        _circuit_breaker.record_success(server_id)
        return result, None

    async def _block(
        self,
        db: AsyncSession,
        *,
        session_id: str,
        org_id: str,
        agent_id: str,
        mcp_server_id: str,
        mcp_server_url: str,
        tool_name: str,
        args_hash: str,
        args_metadata: dict,
        causal_trace_id: str,
        reason: str,
        source_ip: Optional[str],
        policy_decision: str,
    ) -> None:
        """
        Record + audit a blocked call and commit immediately (see module
        docstring point 7).

        policy_decision is required, not defaulted: it is what the
        dashboard labels the block with and what
        aiiam_mcp_tool_denials_total groups by, so every caller must say
        WHICH kind of denial this is — "policy_denied", "provenance_denied",
        "policy_unavailable", "tool_filter_denied", "binding_denied",
        "resource_denied" or "task_scope_denied". (Rows written before this
        distinction existed carry the old catch-all "blocked"; readers
        should treat any unknown value as a generic block.)
        """
        MCP_TOOL_DENIALS_TOTAL.labels(policy_decision=policy_decision).inc()
        await self._record_session(
            db,
            session_id=session_id,
            org_id=org_id,
            agent_id=agent_id,
            mcp_server_id=mcp_server_id,
            mcp_server_url=mcp_server_url,
            tool_name=tool_name,
            args_hash=args_hash,
            args_metadata=args_metadata,
            result_hash=None,
            status="blocked",
            policy_decision=policy_decision,
            # The column is String(255); a longer reason would raise on
            # insert and lose the very record of the block. The full text
            # still goes into the audit entry's details below.
            blocking_reason=reason[:255],
            duration_ms=0,
            causal_trace_id=causal_trace_id,
        )
        await audit_repo.append(
            org_id=org_id,
            action=AuditAction.MCP_TOOL_BLOCKED,
            actor_type="agent",
            actor_id=agent_id,
            agent_id=agent_id,
            causal_trace_id=causal_trace_id,
            outcome="denied",
            resource_type="mcp_tool",
            resource_id=tool_name,
            details={
                "mcp_server_id": mcp_server_id,
                "tool_name": tool_name,
                "args_hash": args_hash,
                "blocking_reason": reason,
            },
            source_ip=source_ip,
        )
        await db.commit()

    async def _record_session(
        self,
        db: AsyncSession,
        **kwargs,
    ) -> McpSession:
        session = McpSession(id=kwargs["session_id"], **{
            k: v for k, v in kwargs.items() if k != "session_id"
        })
        db.add(session)
        await db.flush()
        return session


mcp_proxy_service = McpProxyService()
