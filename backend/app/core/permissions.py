"""
Relationship-based Access Control (ReBAC) via Open Policy Agent (OPA).

Why ReBAC over RBAC:
- RBAC: "Agent has role Admin" → can do everything Admin can
- ReBAC: "Agent A has 'editor' relationship to Resource B" → only that resource
- In multi-agent systems, agents often need scoped access to specific resources
  (e.g., Agent A can read Audit Logs of Org X but not Org Y)

OPA evaluates Rego policies we define — this keeps policy logic OUT of app code
and in version-controlled .rego files. Security teams can audit policies without
reading Python.
"""

import httpx
from typing import Optional
from fastapi import HTTPException, status

from app.core.config import settings


async def verify_opa_reachable() -> None:
    """
    Fail fast at startup if OPA is unreachable — called from main.py's
    lifespan, gated by settings.OPA_REQUIRED (default True).

    check_permission already fails closed on a per-request timeout or
    connection error, so this isn't needed for correctness — it's about
    honesty at boot. A deployment that starts "successfully" with a
    dead policy engine looks healthy from the outside (the HTTP server
    is up) while silently denying every tool call forever; refusing to
    accept traffic at all is the less misleading failure mode.
    """
    if not settings.OPA_REQUIRED:
        return
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{settings.OPA_URL}/health")
            resp.raise_for_status()
    except httpx.HTTPError as e:
        raise RuntimeError(
            f"OPA is required (OPA_REQUIRED=true) but unreachable at "
            f"'{settings.OPA_URL}/health': {e}. Set OPA_REQUIRED=false "
            f"only for narrow local work that doesn't exercise policy "
            f"enforcement."
        ) from e


class PermissionDeniedError(Exception):
    """
    Raised when OPA denies an access request.

    action/resource are optional so this can also be raised with a bare
    message (as tests do, and as ad-hoc denials elsewhere might) without
    fabricating placeholder agent/action/resource values just to satisfy
    a three-argument constructor.
    """
    def __init__(self, agent_id: str, action: Optional[str] = None, resource: Optional[str] = None):
        self.agent_id = agent_id
        self.action = action
        self.resource = resource
        if action is not None and resource is not None:
            message = f"Agent '{agent_id}' denied '{action}' on '{resource}'"
        else:
            message = agent_id
        super().__init__(message)


class ScopeAttenuationError(ValueError):
    """Raised when a delegation would grant a scope the delegator doesn't hold."""


async def check_permission(
    agent_id: str,
    org_id: str,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    token_scopes: list[str] = [],
    delegation_depth: int = 0,
    capabilities: list[str] = [],
    provenance_tainted: bool = False,
) -> bool:
    """
    Evaluate an access decision via OPA.

    OPA receives the full context and evaluates against Rego policies.
    Returns True if allowed, raises PermissionDeniedError if denied.

    Input document sent to OPA:
    {
        "input": {
            "agent_id": "...",
            "org_id": "...",
            "action": "tool:execute",
            "resource": { "type": "mcp_tool", "id": "search_web" },
            "token_scopes": ["tool:execute", "audit:read"],
            "delegation_depth": 1,
            "capabilities": ["external_send"],
            "provenance": { "tainted": false }
        }
    }

    capabilities/provenance (Slice 13) let the policy deny a coarse
    risk category outright — e.g. "external_send" — once the calling
    agent's causal trace has already pulled content this platform
    doesn't control, regardless of scope or depth. Both are resolved
    server-side by the caller (mcp_proxy_service, from the agent's own
    operator-authored mcp_bindings and a query over prior calls in the
    same trace) — never agent-supplied, same trust model as everything
    else this function receives.
    """
    opa_input = {
        "input": {
            "agent_id": agent_id,
            "org_id": org_id,
            "action": action,
            "resource": {
                "type": resource_type,
                **({"id": resource_id} if resource_id else {}),
            },
            "token_scopes": token_scopes,
            "delegation_depth": delegation_depth,
            "capabilities": capabilities,
            "provenance": {"tainted": provenance_tainted},
        }
    }

    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.post(
                f"{settings.OPA_URL}/{settings.OPA_POLICY_PATH}",
                json=opa_input,
            )
            resp.raise_for_status()
            result = resp.json()
    except httpx.TimeoutException:
        # Fail CLOSED on OPA timeout — never default to allow
        raise PermissionDeniedError(
            agent_id, action, resource_id or resource_type
        )
    except httpx.HTTPError:
        raise PermissionDeniedError(
            agent_id, action, resource_id or resource_type
        )

    # OPA returns {"result": {"allow": true/false}}
    allowed = result.get("result", {}).get("allow", False)

    if not allowed:
        raise PermissionDeniedError(agent_id, action, resource_id or resource_type)

    return True


async def require_permission(
    agent_id: str,
    org_id: str,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    token_scopes: list[str] = [],
    delegation_depth: int = 0,
) -> None:
    """
    Decorator-friendly wrapper. Raises HTTP 403 on denial.
    Use this in FastAPI route handlers.
    """
    try:
        await check_permission(
            agent_id, org_id, action, resource_type,
            resource_id, token_scopes, delegation_depth
        )
    except PermissionDeniedError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "permission_denied",
                "agent_id": e.agent_id,
                "action": e.action,
                "resource": e.resource,
            }
        )


def validate_scope_subset(
    requested_scopes: list[str],
    delegating_agent_scopes: list[str],
) -> list[str]:
    """
    Ensure a delegation can ONLY grant scopes the delegating agent already has.

    Prevents privilege escalation: an agent with [read] cannot delegate [write].
    Returns the valid intersection.
    """
    valid = list(set(requested_scopes) & set(delegating_agent_scopes))
    if len(valid) != len(requested_scopes):
        invalid = set(requested_scopes) - set(delegating_agent_scopes)
        raise ScopeAttenuationError(
            f"Requested scopes exceed delegator's active scopes: {invalid}"
        )
    return valid
