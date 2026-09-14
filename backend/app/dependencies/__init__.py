"""
FastAPI dependency injection helpers.

Usage in route handlers:
    @router.get("/agents/{agent_id}")
    async def get_agent(
        agent_id: str,
        db: AsyncSession = Depends(get_db),
        agent: dict = Depends(require_agent_auth),
        org_id: str = Depends(get_org_id),
    ):
        ...
"""

from typing import Optional
from fastapi import Depends, HTTPException, Request, status


async def get_agent_identity(request: Request) -> dict:
    """
    Extract the agent identity set by AgentAuthMiddleware.
    Raises 401 if not present (shouldn't happen if middleware is configured).
    """
    identity = getattr(request.state, "agent", None)
    if not identity:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "not_authenticated"}
        )
    return identity


async def get_causal_trace_id(request: Request) -> str:
    """Extract trace ID set by TracePropagationMiddleware."""
    return getattr(request.state, "causal_trace_id", None) or "unknown"


async def get_source_ip(request: Request) -> Optional[str]:
    """Extract client IP, respecting X-Forwarded-For from reverse proxies."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def require_scope(required_scope: str):
    """
    Dependency factory — inject into a route to require a specific scope.

    Usage:
        @router.post("/tools/execute")
        async def execute_tool(
            agent=Depends(require_scope("tool:execute"))
        ):
    """
    async def _check(agent: dict = Depends(get_agent_identity)) -> dict:
        if required_scope not in agent.get("scopes", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "insufficient_scope",
                    "required": required_scope,
                    "held": agent.get("scopes", []),
                }
            )
        return agent
    return _check
