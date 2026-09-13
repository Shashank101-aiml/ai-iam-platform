"""
Delegation over real HTTP: issue a key for agent A, exchange it, have A
delegate to agent B through the actual /token/delegate route (which is
genuinely agent-authenticated — AgentAuthMiddleware gates this specific
path), then use B's delegation token against an agent-authenticated
route. Also confirms an over-broad delegation request 422s at the HTTP
layer, not just when calling the service directly.

Delegatee agents here are created directly via db_session, not through
POST /api/v1/agents — that route currently 500s on a pre-existing,
separately-tracked bug (agent_service.register() audits before the
agent row it references exists, which real Postgres rejects outright).
Unrelated to what this file verifies.
"""

import uuid
from unittest.mock import patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import AgentStatus
from app.models.agent import Agent
from app.models.organization import Organization
from app.services.mcp_proxy_service import mcp_proxy_service


async def _make_active_agent(
    db_session: AsyncSession,
    org: Organization,
    name: str,
    scopes: list[str],
    mcp_bindings: list[dict] | None = None,
) -> Agent:
    agent = Agent(
        id=str(uuid.uuid4()),
        org_id=org.id,
        name=name,
        status=AgentStatus.ACTIVE,
        allowed_scopes=scopes,
        mcp_bindings=mcp_bindings or [],
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


@pytest.mark.asyncio
async def test_delegation_over_http_reaches_agent_authenticated_route(
    client: AsyncClient,
    operator_token: str,
    test_agent: Agent,
    db_session: AsyncSession,
    test_org: Organization,
):
    delegatee = await _make_active_agent(
        db_session,
        test_org,
        "Delegatee Agent",
        ["tool:execute"],
        mcp_bindings=[
            {"server_id": "srv-1", "server_url": "http://mock-mcp:8080", "tool_filter": ["search_web"]},
        ],
    )

    # Issue and exchange a key for agent A (test_agent), the delegator.
    issue_resp = await client.post(
        f"/api/v1/agents/{test_agent.id}/keys",
        headers={"Authorization": operator_token},
        json={"scopes": ["tool:execute"], "ttl_days": 30},
    )
    assert issue_resp.status_code == 201, issue_resp.text
    key_data = issue_resp.json()
    compound_credential = f"{key_data['key_id']}:{key_data['plaintext_key']}"

    exchange_resp = await client.post(
        "/api/v1/token/exchange",
        json={"grant_type": "api_key", "credential": compound_credential},
    )
    assert exchange_resp.status_code == 200, exchange_resp.text
    agent_a_token = f"Bearer {exchange_resp.json()['access_token']}"

    # A delegates [tool:execute] to B through the real HTTP route.
    delegate_resp = await client.post(
        "/api/v1/token/delegate",
        headers={"Authorization": agent_a_token},
        json={
            "delegatee_agent_id": delegatee.id,
            "requested_scopes": ["tool:execute"],
        },
    )
    assert delegate_resp.status_code == 200, delegate_resp.text
    delegation_data = delegate_resp.json()
    assert delegation_data["delegation_depth"] == 1
    assert delegation_data["scopes"] == ["tool:execute"]
    assert delegation_data["grant"]["delegatee_agent_id"] == delegatee.id
    agent_b_token = f"Bearer {delegation_data['delegation_token']}"

    # B uses its delegation token against a genuinely agent-authenticated route.
    with patch(
        "app.services.mcp_proxy_service.check_permission", return_value=True
    ), patch.object(
        mcp_proxy_service, "_call_mcp_server", return_value=({"result": "ok"}, None)
    ):
        tool_resp = await client.post(
            "/api/v1/mcp/tools/search_web",
            headers={"Authorization": agent_b_token},
            json={
                "mcp_server_id": "srv-1",
                "arguments": {"q": "test"},
            },
        )
    assert tool_resp.status_code == 200, tool_resp.text


@pytest.mark.asyncio
async def test_delegation_over_http_rejects_scope_escalation(
    client: AsyncClient,
    operator_token: str,
    test_agent: Agent,
    db_session: AsyncSession,
    test_org: Organization,
):
    delegatee = await _make_active_agent(
        db_session, test_org, "Escalation Target", ["tool:execute", "super:admin"]
    )

    issue_resp = await client.post(
        f"/api/v1/agents/{test_agent.id}/keys",
        headers={"Authorization": operator_token},
        json={"scopes": ["tool:execute"], "ttl_days": 30},
    )
    assert issue_resp.status_code == 201, issue_resp.text
    key_data = issue_resp.json()
    exchange_resp = await client.post(
        "/api/v1/token/exchange",
        json={
            "grant_type": "api_key",
            "credential": f"{key_data['key_id']}:{key_data['plaintext_key']}",
        },
    )
    assert exchange_resp.status_code == 200, exchange_resp.text
    agent_a_token = f"Bearer {exchange_resp.json()['access_token']}"

    # test_agent's issued key only carries tool:execute — asking to also
    # delegate super:admin must fail, even though the *target* agent's
    # allowed_scopes include it.
    delegate_resp = await client.post(
        "/api/v1/token/delegate",
        headers={"Authorization": agent_a_token},
        json={
            "delegatee_agent_id": delegatee.id,
            "requested_scopes": ["tool:execute", "super:admin"],
        },
    )
    assert delegate_resp.status_code == 422
