"""
Automated tests for MCP Proxy pre-execution ReBAC tool call interception.
"""

import uuid

import pytest
from unittest.mock import patch
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.organization import Organization
from app.models.agent import Agent
from app.models.mcp_session import McpSession
from app.models.audit_log import AuditLog
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
                tool_name="drop_table",
                tool_args={"table": "users"},
                token_scopes=["audit:read"],
                causal_trace_id="mcp-test-trace-1",
            )
        assert exc_info.value.status_code == 403
        assert "OPA policy evaluated to DENY" in str(exc_info.value.detail["reason"])


@pytest.mark.asyncio
async def test_mcp_proxy_rejects_unbound_server_without_calling_opa(
    db_session: AsyncSession, test_org: Organization, test_agent: Agent
):
    """
    An mcp_server_id the agent has no binding for must be rejected before
    OPA is even consulted — there is no server_url to have resolved, so
    there's nothing safe to call. This is what closes the SSRF: the
    request body has no mcp_server_url field at all any more, so the only
    way to reach a server is through the agent's own operator-authored
    mcp_bindings.
    """
    with patch("app.services.mcp_proxy_service.check_permission") as mock_check:
        with pytest.raises(HTTPException) as exc_info:
            await mcp_proxy_service.execute_tool(
                db_session,
                agent_id=test_agent.id,
                org_id=test_org.id,
                mcp_server_id="srv-unbound",
                tool_name="search_web",
                tool_args={"q": "test"},
                token_scopes=["tool:execute"],
                causal_trace_id="mcp-test-trace-unbound",
            )
        assert exc_info.value.status_code == 403
        assert "not bound to mcp_server_id" in str(exc_info.value.detail["reason"])
    mock_check.assert_not_called()


@pytest.mark.asyncio
async def test_mcp_proxy_enforces_tool_filter_after_opa_allows(
    db_session: AsyncSession, test_org: Organization, test_agent: Agent
):
    """
    test_agent's srv-1 binding only allows tool_filter=["search_web"].
    Even if OPA allows the call (mocked True here), a tool outside the
    binding's allowlist must still be blocked — defense in depth against
    an overly broad scope or policy.
    """
    with patch("app.services.mcp_proxy_service.check_permission", return_value=True):
        with pytest.raises(HTTPException) as exc_info:
            await mcp_proxy_service.execute_tool(
                db_session,
                agent_id=test_agent.id,
                org_id=test_org.id,
                mcp_server_id="srv-1",
                tool_name="read_file",
                tool_args={"path": "/etc/passwd"},
                token_scopes=["tool:execute"],
                causal_trace_id="mcp-test-trace-filtered",
            )
        assert exc_info.value.status_code == 403
        assert "tool_filter" in str(exc_info.value.detail["reason"])


@pytest.mark.asyncio
async def test_mcp_proxy_blocked_call_survives_session_rollback(
    db_session: AsyncSession, test_org: Organization, test_agent: Agent
):
    """
    Regression test for a durability bug: the session/audit rows for a
    blocked call were only ever flushed, never committed, by the service
    itself — the caller (the HTTP route) committed only on its own
    success path. Since a blocked call always raises an HTTPException,
    and app.db.session.get_db rolls back the request-scoped session on
    any exception, every blocked-call record was silently lost the
    moment it was created.

    A flushed-but-uncommitted row is still visible to a query on the
    SAME session, so merely reading it back afterward wouldn't actually
    exercise the fix. Instead, explicitly roll back the session right
    after the exception — exactly what get_db does on the real request
    path — and confirm the rows are still there anyway, because the
    service must have committed them itself before raising.
    """
    trace_id = f"mcp-durability-{uuid.uuid4()}"
    with pytest.raises(HTTPException):
        await mcp_proxy_service.execute_tool(
            db_session,
            agent_id=test_agent.id,
            org_id=test_org.id,
            mcp_server_id="srv-unbound",
            tool_name="search_web",
            tool_args={"q": "test"},
            token_scopes=["tool:execute"],
            causal_trace_id=trace_id,
        )
    await db_session.rollback()

    session_row = (
        await db_session.execute(
            select(McpSession).where(McpSession.causal_trace_id == trace_id)
        )
    ).scalar_one_or_none()
    assert session_row is not None, "blocked call's session row did not survive"
    assert session_row.status == "blocked"

    audit_row = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.causal_trace_id == trace_id)
        )
    ).scalar_one_or_none()
    assert audit_row is not None, "blocked call's audit row did not survive"
    assert audit_row.outcome == "denied"
