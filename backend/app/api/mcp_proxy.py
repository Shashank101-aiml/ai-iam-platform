"""
MCP Proxy Router.
Intercepts tool execution requests (`/tools/{tool_name}`) pre-execution, evaluates
ReBAC rules via Open Policy Agent, hashes arguments (`_hash_payload`), and records outcomes.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, status, Request, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.mcp_session import (
    McpToolExecuteRequest,
    McpToolExecuteResponse,
    McpSessionLogResponse,
)
from app.services.mcp_proxy_service import mcp_proxy_service
from app.repositories.mcp_session_repo import mcp_session_repo
from app.api.deps import get_current_agent_state, get_current_user
from app.models.user import User
from app.services.mcp_proxy_service import _hash_payload

router = APIRouter()


@router.post("/tools/{tool_name}", response_model=McpToolExecuteResponse)
async def execute_mcp_tool(
    tool_name: str,
    exec_in: McpToolExecuteRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_agent: dict = Depends(get_current_agent_state),
):
    """
    Execute an MCP tool subject to pre-execution ReBAC interception.
    Extracts agent identity and scopes from JWT (`request.state.agent`).

    mcp_server_url is intentionally not part of the request — it's
    resolved server-side from the agent's own mcp_bindings by
    mcp_server_id (see mcp_proxy_service._resolve_mcp_binding), so an
    agent can't redirect the proxy's outbound call to an arbitrary
    address.
    """
    trace_id = exec_in.causal_trace_id or current_agent.get("causal_trace_id", "mcp:exec")
    result = await mcp_proxy_service.execute_tool(
        db,
        agent_id=current_agent["agent_id"],
        org_id=current_agent["org_id"],
        mcp_server_id=exec_in.mcp_server_id,
        tool_name=tool_name,
        tool_args=exec_in.arguments,
        token_scopes=current_agent.get("scopes", []),
        causal_trace_id=trace_id,
        delegation_depth=current_agent.get("delegation_depth", 0),
        source_ip=request.client.host if request.client else None,
    )

    # Compute hashes for response DTO match
    args_hash = _hash_payload(exec_in.arguments)
    result_hash = _hash_payload(result["result"]) if result.get("result") is not None else ""
    return {
        "session_id": result["session_id"],
        "tool_name": result["tool_name"],
        "status": "success",
        "result": result["result"],
        "args_hash": args_hash,
        "result_hash": result_hash,
        "duration_ms": result["duration_ms"],
        "policy_decision": "allowed",
    }


@router.get("/sessions", response_model=List[McpSessionLogResponse])
async def list_mcp_sessions(
    agent_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List proxy tool execution logs for operator verification."""
    if agent_id:
        return await mcp_session_repo.get_by_agent(
            db, agent_id=agent_id, org_id=current_user.org_id, limit=limit, tool_name=tool_name
        )
    else:
        # Return blocked or latest across org
        from sqlalchemy import select
        from app.models.mcp_session import McpSession
        result = await db.execute(
            select(McpSession).where(McpSession.org_id == current_user.org_id).order_by(McpSession.created_at.desc()).limit(limit)
        )
        return result.scalars().all()
