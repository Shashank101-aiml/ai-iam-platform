"""
GET /overview/counts — the live totals behind the dashboard's navigation badges.

Counts must be real totals (not a page's worth), exact, and strictly scoped
to the caller's own organization.
"""

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import AgentStatus
from app.models.agent import Agent
from app.models.mcp_session import McpSession
from app.models.organization import Organization


def _session(org_id: str, agent_id: str, status: str, decision: str) -> McpSession:
    return McpSession(
        id=str(uuid.uuid4()),
        org_id=org_id,
        agent_id=agent_id,
        mcp_server_id="srv-1",
        mcp_server_url="http://mock-mcp:8080",
        tool_name="search_web",
        status=status,
        policy_decision=decision,
        source_untrusted=False,
        causal_trace_id=f"overview-{uuid.uuid4()}",
    )


@pytest.mark.asyncio
async def test_counts_require_authentication(client: AsyncClient):
    response = await client.get("/api/v1/overview/counts")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_a_new_org_counts_zero_everywhere(
    client: AsyncClient, operator_token: str, test_org: Organization
):
    response = await client.get("/api/v1/overview/counts", headers={"Authorization": operator_token})
    assert response.status_code == 200
    assert response.json() == {
        "agents": 0, "sub_agents": 0, "audit_entries": 0, "mcp_calls": 0, "mcp_blocked": 0,
    }


@pytest.mark.asyncio
async def test_counts_are_exact_and_agree_with_the_data_they_summarise(
    client: AsyncClient, db_session: AsyncSession, operator_token: str, test_org: Organization
):
    headers = {"Authorization": operator_token}
    parent = await client.post("/api/v1/agents", headers=headers, json={"name": "Parent"})
    child = await client.post(
        "/api/v1/agents", headers=headers,
        json={"name": "Child", "parent_agent_id": parent.json()["id"]},
    )
    assert parent.status_code == 201 and child.status_code == 201

    db_session.add_all([
        _session(test_org.id, parent.json()["id"], "success", "allowed"),
        _session(test_org.id, parent.json()["id"], "blocked", "tool_filter_denied"),
        _session(test_org.id, parent.json()["id"], "blocked", "policy_denied"),
    ])
    await db_session.commit()

    counts = (await client.get("/api/v1/overview/counts", headers=headers)).json()
    assert counts["agents"] == 2
    assert counts["sub_agents"] == 1
    assert counts["mcp_calls"] == 3
    assert counts["mcp_blocked"] == 2

    # Cross-check against what the tabs themselves list, so a badge can never disagree with its tab.
    assert counts["agents"] == len((await client.get("/api/v1/agents", headers=headers)).json())
    assert counts["audit_entries"] == len((await client.get("/api/v1/audit/logs", headers=headers)).json())
    assert counts["audit_entries"] >= 2  # at least the two agent.registered entries


@pytest.mark.asyncio
async def test_counts_never_include_another_orgs_data(
    client: AsyncClient, db_session: AsyncSession, operator_token: str, test_org: Organization
):
    other = Organization(id=str(uuid.uuid4()), name="Other Corp", slug="other-corp", is_active=True)
    db_session.add(other)
    await db_session.commit()
    stranger = Agent(
        id=str(uuid.uuid4()), org_id=other.id, name="Stranger", status=AgentStatus.ACTIVE,
        allowed_scopes=["tool:execute"],
    )
    stranger_child = Agent(
        id=str(uuid.uuid4()), org_id=other.id, name="Stranger child", status=AgentStatus.ACTIVE,
        allowed_scopes=["tool:execute"], parent_agent_id=stranger.id,
    )
    db_session.add(stranger)
    await db_session.commit()
    db_session.add(stranger_child)
    db_session.add(_session(other.id, stranger.id, "blocked", "policy_denied"))
    await db_session.commit()

    # operator_token belongs to a SUPERUSER in test_org — superusers still only get their own org's counts.
    counts = (await client.get("/api/v1/overview/counts", headers={"Authorization": operator_token})).json()
    assert counts == {"agents": 0, "sub_agents": 0, "audit_entries": 0, "mcp_calls": 0, "mcp_blocked": 0}
