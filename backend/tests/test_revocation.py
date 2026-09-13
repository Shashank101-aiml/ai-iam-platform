"""
Slice 9 regression tests: revocation actually works. Short token TTLs
limit exposure but are not revocation — every path here used to only
flip a database flag the auth path never consulted. These tests prove
an already-issued token stops working immediately (well before its
natural expiry), not just that new tokens stop being issuable.

/api/v1/token/delegate is used as the generic "is this agent token
still accepted" probe: it's genuinely agent-authenticated
(AgentAuthMiddleware gates it), so AgentAuthMiddleware's revocation
check runs and rejects a revoked token with 401 before the route body
(which would otherwise need a valid delegatee/scopes) ever runs.
"""

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import AgentStatus
from app.models.agent import Agent
from app.models.organization import Organization


async def _make_active_agent(
    db_session: AsyncSession, org: Organization, name: str, scopes: list[str]
) -> Agent:
    agent = Agent(
        id=str(uuid.uuid4()),
        org_id=org.id,
        name=name,
        status=AgentStatus.ACTIVE,
        allowed_scopes=scopes,
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


async def _issue_and_exchange(
    client: AsyncClient, operator_token: str, agent: Agent, scopes: list[str]
) -> str:
    """Issue a key for `agent` and exchange it for a Bearer access token string."""
    issue_resp = await client.post(
        f"/api/v1/agents/{agent.id}/keys",
        headers={"Authorization": operator_token},
        json={"scopes": scopes, "ttl_days": 30},
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
    return f"Bearer {exchange_resp.json()['access_token']}", key_data["key_id"]


def _probe(client: AsyncClient, token: str):
    """A cheap, generic 'does this agent token still work' HTTP call."""
    return client.post(
        "/api/v1/token/delegate",
        headers={"Authorization": token},
        json={"delegatee_agent_id": "irrelevant-for-this-probe", "requested_scopes": ["tool:execute"]},
    )


@pytest.mark.asyncio
async def test_delegation_grant_revocation_rejects_token_immediately(
    client: AsyncClient, operator_token: str, test_agent: Agent, db_session: AsyncSession, test_org: Organization
):
    delegatee = await _make_active_agent(db_session, test_org, "Delegatee A", ["tool:execute"])
    agent_a_token, _ = await _issue_and_exchange(client, operator_token, test_agent, ["tool:execute"])

    delegate_resp = await client.post(
        "/api/v1/token/delegate",
        headers={"Authorization": agent_a_token},
        json={"delegatee_agent_id": delegatee.id, "requested_scopes": ["tool:execute"]},
    )
    assert delegate_resp.status_code == 200, delegate_resp.text
    grant_id = delegate_resp.json()["grant"]["id"]
    delegatee_token = f"Bearer {delegate_resp.json()['delegation_token']}"

    # The token is genuinely valid before revocation.
    pre_revoke = await _probe(client, delegatee_token)
    assert pre_revoke.status_code != 401

    revoke_resp = await client.post(
        f"/api/v1/token/delegations/{grant_id}/revoke",
        headers={"Authorization": operator_token},
        json={"reason": "test revocation"},
    )
    assert revoke_resp.status_code == 200, revoke_resp.text
    assert revoke_resp.json()["revoked"] is True
    assert revoke_resp.json()["descendant_grants_revoked"] == 0

    post_revoke = await _probe(client, delegatee_token)
    assert post_revoke.status_code == 401
    assert post_revoke.json()["error"] == "token_revoked"


@pytest.mark.asyncio
async def test_delegation_revocation_cascades_to_child_grant(
    client: AsyncClient, operator_token: str, test_agent: Agent, db_session: AsyncSession, test_org: Organization
):
    """Revoking A→B must also invalidate the already-issued B→C token, one hop down."""
    agent_b = await _make_active_agent(db_session, test_org, "Agent B", ["tool:execute"])
    agent_c = await _make_active_agent(db_session, test_org, "Agent C", ["tool:execute"])

    agent_a_token, _ = await _issue_and_exchange(client, operator_token, test_agent, ["tool:execute"])

    ab_resp = await client.post(
        "/api/v1/token/delegate",
        headers={"Authorization": agent_a_token},
        json={"delegatee_agent_id": agent_b.id, "requested_scopes": ["tool:execute"]},
    )
    assert ab_resp.status_code == 200, ab_resp.text
    ab_grant_id = ab_resp.json()["grant"]["id"]
    agent_b_token = f"Bearer {ab_resp.json()['delegation_token']}"

    bc_resp = await client.post(
        "/api/v1/token/delegate",
        headers={"Authorization": agent_b_token},
        json={"delegatee_agent_id": agent_c.id, "requested_scopes": ["tool:execute"]},
    )
    assert bc_resp.status_code == 200, bc_resp.text
    agent_c_token = f"Bearer {bc_resp.json()['delegation_token']}"

    # C's token works before the ancestor grant is revoked.
    assert (await _probe(client, agent_c_token)).status_code != 401

    revoke_resp = await client.post(
        f"/api/v1/token/delegations/{ab_grant_id}/revoke",
        headers={"Authorization": operator_token},
        json={"reason": "cascade test"},
    )
    assert revoke_resp.status_code == 200, revoke_resp.text
    assert revoke_resp.json()["descendant_grants_revoked"] == 1

    # Both B's own token AND C's (one hop further down) must now be dead.
    b_probe = await _probe(client, agent_b_token)
    assert b_probe.status_code == 401
    assert b_probe.json()["error"] == "token_revoked"

    c_probe = await _probe(client, agent_c_token)
    assert c_probe.status_code == 401
    assert c_probe.json()["error"] == "token_revoked"


@pytest.mark.asyncio
async def test_suspending_agent_revokes_its_access_token(
    client: AsyncClient, operator_token: str, test_agent: Agent
):
    agent_token, _ = await _issue_and_exchange(client, operator_token, test_agent, ["tool:execute"])
    assert (await _probe(client, agent_token)).status_code != 401

    suspend_resp = await client.post(
        f"/api/v1/agents/{test_agent.id}/suspend",
        headers={"Authorization": operator_token},
        json={"status": AgentStatus.SUSPENDED, "reason": "test suspension"},
    )
    assert suspend_resp.status_code == 200, suspend_resp.text

    post_suspend = await _probe(client, agent_token)
    assert post_suspend.status_code == 401
    assert post_suspend.json()["error"] == "token_revoked"


@pytest.mark.asyncio
async def test_revoking_api_key_rejects_its_already_issued_token(
    client: AsyncClient, operator_token: str, test_agent: Agent
):
    agent_token, key_id = await _issue_and_exchange(client, operator_token, test_agent, ["tool:execute"])
    assert (await _probe(client, agent_token)).status_code != 401

    revoke_resp = await client.delete(
        f"/api/v1/keys/{key_id}",
        headers={"Authorization": operator_token},
    )
    assert revoke_resp.status_code == 204, revoke_resp.text

    post_revoke = await _probe(client, agent_token)
    assert post_revoke.status_code == 401
    assert post_revoke.json()["error"] == "token_revoked"


@pytest.mark.asyncio
async def test_revocation_check_fails_closed_when_redis_unreachable(
    client: AsyncClient, operator_token: str, test_agent: Agent, monkeypatch
):
    """
    A revocation index that can't be reached must deny, not silently
    trust the token — same fail-closed choice this project already made
    for OPA. Distinguishable from an actual revocation via the error
    code (revocation_check_unavailable, not token_revoked).
    """
    agent_token, _ = await _issue_and_exchange(client, operator_token, test_agent, ["tool:execute"])

    from app.core import revocation as revocation_module

    broken_client = revocation_module.redis.from_url("redis://127.0.0.1:1/0", decode_responses=True)
    monkeypatch.setattr(revocation_module, "_redis_client", broken_client)

    resp = await _probe(client, agent_token)
    assert resp.status_code == 401
    assert resp.json()["error"] == "revocation_check_unavailable"
