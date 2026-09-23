"""
Each kind of MCP block is recorded and reported as what it actually was.

Before this, every block was stored as policy_decision="blocked" and shown
as "OPA REBAC BLOCKED" — including a tool_filter block OPA never saw — and
a provenance denial read only "denied 'tool:execute' on 'send_email'", with
no hint that the real cause was an earlier untrusted read in the same trace.

Runs against the REAL OPA instance and authz.rego (like test_opa_policy.py
and test_provenance_authz.py): the point is that OPA's own deny_reasons
reach the audit trail, not that a mocked check_permission was called.
_call_mcp_server is mocked so no downstream server is needed.
"""

import uuid
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import (
    PermissionDeniedError,
    REASON_POLICY_UNAVAILABLE,
    REASON_PROVENANCE,
    check_permission,
)
from app.models.agent import Agent
from app.models.mcp_session import McpSession
from app.models.organization import Organization
from app.services.mcp_proxy_service import _classify_policy_denial, mcp_proxy_service

BINDINGS = [
    {"server_id": "srv-1", "server_url": "http://mock-mcp:8080", "tool_filter": ["search_web"]},
    {"server_id": "web-mcp", "server_url": "http://mock-mcp:8080", "tool_filter": ["search_web"], "untrusted_source": True},
    {
        "server_id": "comms-mcp",
        "server_url": "http://mock-mcp:8080",
        "tool_filter": ["send_email"],
        "tool_capabilities": {"send_email": ["external_send"]},
    },
]


async def _prepare(db_session: AsyncSession, agent: Agent) -> None:
    await db_session.execute(update(Agent).where(Agent.id == agent.id).values(mcp_bindings=BINDINGS))
    await db_session.commit()


async def _blocked_row(db_session: AsyncSession, trace_id: str) -> McpSession:
    return (
        await db_session.execute(
            select(McpSession).where(McpSession.causal_trace_id == trace_id, McpSession.status == "blocked")
        )
    ).scalar_one()


async def _call(db_session, org, agent, *, server, tool, scopes, trace_id):
    return await mcp_proxy_service.execute_tool(
        db_session,
        agent_id=agent.id,
        org_id=org.id,
        mcp_server_id=server,
        tool_name=tool,
        tool_args={},
        token_scopes=scopes,
        causal_trace_id=trace_id,
    )


# ── pure classification ──────────────────────────────────────────────

def test_classify_provenance_only():
    decision, reason = _classify_policy_denial(
        PermissionDeniedError("a1", "tool:execute", "send_email", reasons=[REASON_PROVENANCE]),
        "send_email", ["external_send"],
    )
    assert decision == "provenance_denied"
    assert "provenance" in reason and "external_send" in reason and "untrusted" in reason


def test_classify_policy_unavailable_fails_closed_wording():
    decision, reason = _classify_policy_denial(
        PermissionDeniedError("a1", "tool:execute", "t", reasons=[REASON_POLICY_UNAVAILABLE]), "t", [],
    )
    assert decision == "policy_unavailable"
    assert "failed closed" in reason


def test_classify_multiple_reasons_is_policy_denied_and_lists_all():
    decision, reason = _classify_policy_denial(
        PermissionDeniedError("a1", "tool:execute", "t", reasons=["scope_not_granted", REASON_PROVENANCE]), "t", [],
    )
    assert decision == "policy_denied"  # not only provenance, so not labelled as such
    assert "tool:execute scope" in reason and "untrusted" in reason


def test_classify_unknown_code_passes_through_and_no_reasons_is_plain():
    decision, reason = _classify_policy_denial(
        PermissionDeniedError("a1", "tool:execute", "t", reasons=["some_future_reason"]), "t", [],
    )
    assert decision == "policy_denied" and "some_future_reason" in reason
    decision, reason = _classify_policy_denial(PermissionDeniedError("bare message"), "t", [])
    assert (decision, reason) == ("policy_denied", "bare message")


# ── OPA's own reasons reach check_permission ─────────────────────────

@pytest.mark.asyncio
async def test_check_permission_carries_opas_deny_reasons():
    common = dict(agent_id="a1", org_id="o1", action="tool:execute", resource_type="mcp_tool")

    with pytest.raises(PermissionDeniedError) as e:
        await check_permission(**common, resource_id="send_email", token_scopes=["tool:execute"],
                               capabilities=["external_send"], provenance_tainted=True)
    assert e.value.reasons == [REASON_PROVENANCE]

    with pytest.raises(PermissionDeniedError) as e:
        await check_permission(**common, resource_id="search_web", token_scopes=["audit:read"])
    assert e.value.reasons == ["scope_not_granted"]

    with pytest.raises(PermissionDeniedError) as e:
        await check_permission(**common, resource_id="delete_database", token_scopes=["tool:execute"])
    assert e.value.reasons == ["blocked_tool"]

    assert await check_permission(**common, resource_id="search_web", token_scopes=["tool:execute"]) is True


# ── each block kind, recorded and reported as what it was ────────────

@pytest.mark.asyncio
async def test_provenance_denial_is_recorded_and_explained(
    db_session: AsyncSession, test_org: Organization, test_agent: Agent
):
    await _prepare(db_session, test_agent)
    trace = f"cls-provenance-{uuid.uuid4()}"
    with patch.object(mcp_proxy_service, "_call_mcp_server", return_value=({"ok": True}, None)):
        await _call(db_session, test_org, test_agent, server="web-mcp", tool="search_web", scopes=["tool:execute"], trace_id=trace)
        with pytest.raises(HTTPException) as exc:
            await _call(db_session, test_org, test_agent, server="comms-mcp", tool="send_email", scopes=["tool:execute"], trace_id=trace)

    row = await _blocked_row(db_session, trace)
    assert row.policy_decision == "provenance_denied"
    assert "provenance" in row.blocking_reason and "external_send" in row.blocking_reason
    assert exc.value.detail["reason"] == row.blocking_reason


@pytest.mark.asyncio
async def test_missing_scope_and_blocked_tool_are_policy_denied_with_specific_reasons(
    db_session: AsyncSession, test_org: Organization, test_agent: Agent
):
    await _prepare(db_session, test_agent)

    t1 = f"cls-scope-{uuid.uuid4()}"
    with pytest.raises(HTTPException):
        await _call(db_session, test_org, test_agent, server="srv-1", tool="search_web", scopes=["audit:read"], trace_id=t1)
    row = await _blocked_row(db_session, t1)
    assert row.policy_decision == "policy_denied" and "tool:execute scope" in row.blocking_reason

    t2 = f"cls-blocked-tool-{uuid.uuid4()}"
    with pytest.raises(HTTPException):
        await _call(db_session, test_org, test_agent, server="srv-1", tool="delete_database", scopes=["tool:execute"], trace_id=t2)
    row = await _blocked_row(db_session, t2)
    assert row.policy_decision == "policy_denied" and "always-blocked" in row.blocking_reason


@pytest.mark.asyncio
async def test_tool_filter_block_is_not_labelled_as_a_policy_denial(
    db_session: AsyncSession, test_org: Organization, test_agent: Agent
):
    await _prepare(db_session, test_agent)
    trace = f"cls-filter-{uuid.uuid4()}"
    # OPA allows this (scope present, tool not blocked); only the binding's tool_filter refuses it.
    with pytest.raises(HTTPException):
        await _call(db_session, test_org, test_agent, server="srv-1", tool="read_file", scopes=["tool:execute"], trace_id=trace)
    row = await _blocked_row(db_session, trace)
    assert row.policy_decision == "tool_filter_denied"
    assert "tool_filter" in row.blocking_reason


@pytest.mark.asyncio
async def test_unbound_server_is_binding_denied(
    db_session: AsyncSession, test_org: Organization, test_agent: Agent
):
    await _prepare(db_session, test_agent)
    trace = f"cls-binding-{uuid.uuid4()}"
    with pytest.raises(HTTPException):
        await _call(db_session, test_org, test_agent, server="nope", tool="search_web", scopes=["tool:execute"], trace_id=trace)
    assert (await _blocked_row(db_session, trace)).policy_decision == "binding_denied"


@pytest.mark.asyncio
async def test_unreachable_opa_fails_closed_and_says_so(
    db_session: AsyncSession, test_org: Organization, test_agent: Agent
):
    await _prepare(db_session, test_agent)
    trace = f"cls-unavailable-{uuid.uuid4()}"
    with patch("app.core.permissions.settings.OPA_URL", "http://127.0.0.1:1"):
        with pytest.raises(HTTPException) as exc:
            await _call(db_session, test_org, test_agent, server="srv-1", tool="search_web", scopes=["tool:execute"], trace_id=trace)
    assert exc.value.status_code == 403  # still denied, never allowed by default
    row = await _blocked_row(db_session, trace)
    assert row.policy_decision == "policy_unavailable"
    assert "failed closed" in row.blocking_reason
