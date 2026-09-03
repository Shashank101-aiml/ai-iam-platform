"""
MCP Proxy Service — intercepts every tool call before execution.

This is what makes the platform genuinely useful in production:
instead of just recording THAT an agent called a tool, we intercept
BEFORE the call and can block it based on policy.

Flow:
  Agent → our proxy → OPA policy check → MCP server (if allowed)
                   ↘ blocked (if denied) → audit log

Security properties:
1. Policy enforcement BEFORE execution — not logging after the fact
2. Args are hashed, not stored (may contain secrets)
3. Results are hashed, not stored (may contain sensitive data)
4. Every call linked to the agent's causal trace for full reconstruction
5. Duration tracking catches abnormally slow tool calls (potential DoS)
"""

import uuid
import time
import json
import hashlib
from typing import Optional, Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException

from app.models.mcp_session import McpSession
from app.core.constants import AuditAction
from app.core.permissions import check_permission, PermissionDeniedError
from app.repositories.audit_repo import audit_repo


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


class McpProxyService:

    async def execute_tool(
        self,
        db: AsyncSession,
        *,
        agent_id: str,
        org_id: str,
        mcp_server_id: str,
        mcp_server_url: str,
        tool_name: str,
        tool_args: dict,
        token_scopes: list[str],
        causal_trace_id: str,
        delegation_depth: int = 0,
        source_ip: Optional[str] = None,
    ) -> dict:
        """
        Proxy a tool call through policy enforcement.

        Steps:
        1. OPA policy check (fail closed)
        2. If allowed: forward to MCP server
        3. Record session with hashed args/results
        4. Emit audit event
        5. Return result to agent
        """
        session_id = str(uuid.uuid4())
        args_hash = _hash_payload(tool_args)
        args_metadata = _safe_args_metadata(tool_args)
        start_time = time.monotonic()

        # Step 1: Policy enforcement BEFORE the call
        try:
            await check_permission(
                agent_id=agent_id,
                org_id=org_id,
                action="tool:execute",
                resource_type="mcp_tool",
                resource_id=tool_name,
                token_scopes=token_scopes,
                delegation_depth=delegation_depth,
            )
        except PermissionDeniedError as e:
            # Blocked — record and return immediately, no MCP call made
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
                policy_decision="blocked",
                blocking_reason=str(e),
                duration_ms=0,
                causal_trace_id=causal_trace_id,
            )
            await audit_repo.append(
                db,
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
                    "blocking_reason": str(e),
                },
                source_ip=source_ip,
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "tool_call_blocked",
                    "tool": tool_name,
                    "reason": str(e),
                    "session_id": session_id,
                },
            )

        # Step 2: Forward to actual MCP server
        result, error_code = await self._call_mcp_server(
            mcp_server_url, tool_name, tool_args
        )
        duration_ms = int((time.monotonic() - start_time) * 1000)
        call_status = "success" if error_code is None else "error"
        result_hash = _hash_payload(result) if result is not None else None

        # Step 3: Record session with hashes only
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
            result_hash=result_hash,
            status=call_status,
            policy_decision="allowed",
            blocking_reason=None,
            duration_ms=duration_ms,
            causal_trace_id=causal_trace_id,
            error_code=error_code,
        )

        # Step 4: Audit event
        await audit_repo.append(
            db,
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

    async def _call_mcp_server(
        self,
        server_url: str,
        tool_name: str,
        args: dict,
    ) -> tuple[Optional[dict], Optional[str]]:
        """
        Forward the tool call to the actual MCP server.
        Returns (result, error_code). error_code is None on success.
        """
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{server_url}/tools/{tool_name}",
                    json={"arguments": args},
                    headers={"Content-Type": "application/json"},
                )
                if response.status_code == 200:
                    return response.json(), None
                else:
                    return None, f"mcp_http_{response.status_code}"
        except httpx.TimeoutException:
            return None, "mcp_timeout"
        except httpx.ConnectError:
            return None, "mcp_connection_refused"
        except Exception as e:
            return None, f"mcp_error:{type(e).__name__}"

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
