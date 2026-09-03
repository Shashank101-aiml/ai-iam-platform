"""
Automated tests for Agent Lifecycle management (`register`, `activate`, `suspend`, `decommission`).
"""

import pytest
from httpx import AsyncClient
from app.models.organization import Organization
from app.models.agent import Agent
from app.core.constants import AgentStatus


@pytest.mark.asyncio
async def test_register_agent_creates_pending_state(
    client: AsyncClient, operator_token: str, test_org: Organization
):
    """Verifies that newly registered agents start in PENDING state."""
    response = await client.post(
        "/api/v1/agents",
        headers={"Authorization": operator_token},
        json={
            "name": "Data Analyst Agent",
            "description": "SQL and pandas data analytics bot",
            "allowed_scopes": ["data:read", "sql:query"],
            "max_delegation_depth": 2,
            "is_ephemeral": False,
        },
    )
    assert response.status_code == 201, response.text
    data = response.json()
    assert data["name"] == "Data Analyst Agent"
    assert data["status"] == AgentStatus.PENDING
    assert data["spiffe_id"] is None


@pytest.mark.asyncio
async def test_activate_agent_provisions_spiffe(
    client: AsyncClient, operator_token: str, test_org: Organization
):
    """Verifies that activating an agent transitions it to ACTIVE and assigns SPIFFE ID."""
    # 1. Register
    reg_resp = await client.post(
        "/api/v1/agents",
        headers={"Authorization": operator_token},
        json={
            "name": "SPIFFE Worker",
            "allowed_scopes": ["worker:run"],
        },
    )
    agent_id = reg_resp.json()["id"]

    # 2. Activate
    act_resp = await client.post(
        f"/api/v1/agents/{agent_id}/activate",
        headers={"Authorization": operator_token},
    )
    assert act_resp.status_code == 200, act_resp.text
    data = act_resp.json()
    assert data["status"] == AgentStatus.ACTIVE
    assert data["spiffe_id"] == f"spiffe://ai-iam.internal/ns/{test_org.id}/sa/{agent_id}"


@pytest.mark.asyncio
async def test_suspend_and_decommission_flow(
    client: AsyncClient, operator_token: str, test_agent: Agent
):
    """Verifies suspension and irreversible decommissioning lifecycle."""
    # Suspend
    susp_resp = await client.post(
        f"/api/v1/agents/{test_agent.id}/suspend",
        headers={"Authorization": operator_token},
        json={"status": AgentStatus.SUSPENDED, "reason": "Security investigation"},
    )
    assert susp_resp.status_code == 200
    assert susp_resp.json()["status"] == AgentStatus.SUSPENDED

    # Decommission
    decom_resp = await client.post(
        f"/api/v1/agents/{test_agent.id}/decommission",
        headers={"Authorization": operator_token},
        json={"status": AgentStatus.DECOMMISSIONED, "reason": "End of lifecycle"},
    )
    assert decom_resp.status_code == 200
    assert decom_resp.json()["status"] == AgentStatus.DECOMMISSIONED
