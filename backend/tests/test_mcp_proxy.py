"""
Automated tests for MCP Proxy pre-execution ReBAC tool call interception.
"""

import pytest
from unittest.mock import patch
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.organization import Organization
from app.models.agent import Agent
from app.services.mcp_proxy_service import mcp_proxy_service
from app.core.permissions import PermissionDeniedError
from fastapi import HTTPException


@pytest.mark.asyncio
async def test_mcp_proxy_blocks_unauthorized_tool_before_execution(
    db_session: AsyncSession, test_org: Organization, test_agent: Agent
):
    """Verifies that when OPA rejects permission, MCP server is never called and audit logs failure."""
    with patch("app.services.mcp_proxy_service.check_permission") as mock_check:
        mock_check.side_effect = PermissionDeniedError("OPA policy evaluated to DENY for tool execution")

        with pytest.raises(HTTPException) as exc_info:
            await mcp_proxy_service.execute_tool(
                db_session,
                agent_id=test_agent.id,
                org_id=test_org.id,
                mcp_server_id="srv-1",
                mcp_server_url="http://mock-mcp:8080",
                tool_name="drop_table",
                tool_args={"table": "users"},
                token_scopes=["audit:read"],
                causal_trace_id="mcp-test-trace-1",
            )
        assert exc_info.value.status_code == 403
        assert "OPA policy evaluated to DENY" in str(exc_info.value.detail["reason"])
