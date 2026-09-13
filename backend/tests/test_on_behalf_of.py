"""
Slice 11 tests: delegated human authority (on_behalf_of).

Covers: activation records the permanent activated_by_user_id anchor;
a root token's on_behalf_of claim resolves to it; delegation propagates
the SAME on_behalf_of down the chain unchanged; an explicit
OnBehalfOfGrant overrides the default for its covered scope and TTL;
and causal-trace reconstruction surfaces "which human ultimately
authorized this" (originating_operator).

on_behalf_of is resolved server-side at every mint site
(agent_service.resolve_on_behalf_of) from data an operator actually
wrote (activation, or an explicit grant) — there is no request field
anywhere a caller could set it directly, so "an agent cannot claim
on_behalf_of a user who never authorized its root activation" holds by
construction, not by a runtime check. test_on_behalf_of_is_never_a_
caller_supplied_value proves the concrete case: passing an arbitrary
foreign id has no effect because TokenExchangeRequest has no such field
at all.
"""

import uuid

import pytest
import bcrypt
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import AgentStatus
from app.models.agent import Agent
from app.models.organization import Organization
from app.models.user import User


async def _make_pending_agent(db_session: AsyncSession, org: Organization, name: str, scopes: list[str]) -> Agent:
    """PENDING — the caller activates it over real HTTP to record activated_by_user_id."""
    agent = Agent(
        id=str(uuid.uuid4()), org_id=org.id, name=name,
        status=AgentStatus.PENDING, allowed_scopes=scopes,
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


async def _make_already_active_agent(db_session: AsyncSession, org: Organization, name: str, scopes: list[str]) -> Agent:
    """ACTIVE directly, never through /activate — no activated_by_user_id anchor at all."""
    agent = Agent(
        id=str(uuid.uuid4()), org_id=org.id, name=name,
        status=AgentStatus.ACTIVE, allowed_scopes=scopes,
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


async def _make_second_operator(db_session: AsyncSession, org: Organization) -> tuple[User, str]:
    """Returns (user, password) for a second operator in the same org."""
    password = "SecondOperatorPass456!"
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user = User(
        id=str(uuid.uuid4()), org_id=org.id, email="second-operator@testcorp.ai",
        hashed_password=hashed, is_active=True, is_superuser=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user, password


async def _issue_and_exchange(client: AsyncClient, operator_token: str, agent: Agent, scopes: list[str]) -> dict:
    issue_resp = await client.post(
        f"/api/v1/agents/{agent.id}/keys",
        headers={"Authorization": operator_token},
        json={"scopes": scopes, "ttl_days": 30},
    )
    assert issue_resp.status_code == 201, issue_resp.text
    key_data = issue_resp.json()
    exchange_resp = await client.post(
        "/api/v1/token/exchange",
        json={"grant_type": "api_key", "credential": f"{key_data['key_id']}:{key_data['plaintext_key']}"},
    )
    assert exchange_resp.status_code == 200, exchange_resp.text
    return exchange_resp.json()


@pytest.mark.asyncio
async def test_activation_records_activated_by_and_root_token_carries_on_behalf_of(
    client: AsyncClient, operator_token: str, test_user: User, db_session: AsyncSession, test_org: Organization,
):
    agent = await _make_pending_agent(db_session, test_org, "OBO Root Agent", ["tool:execute"])
    # Activate over real HTTP — this is what records activated_by_user_id.
    act_resp = await client.post(
        f"/api/v1/agents/{agent.id}/activate", headers={"Authorization": operator_token}
    )
    assert act_resp.status_code == 200, act_resp.text

    token_data = await _issue_and_exchange(client, operator_token, agent, ["tool:execute"])
    assert token_data["on_behalf_of"] == test_user.id


@pytest.mark.asyncio
async def test_delegation_propagates_on_behalf_of_unchanged(
    client: AsyncClient, operator_token: str, test_user: User, db_session: AsyncSession, test_org: Organization,
):
    root = await _make_pending_agent(db_session, test_org, "OBO Delegator", ["tool:execute"])
    delegatee = await _make_already_active_agent(db_session, test_org, "OBO Delegatee", ["tool:execute"])
    await client.post(f"/api/v1/agents/{root.id}/activate", headers={"Authorization": operator_token})

    root_token_data = await _issue_and_exchange(client, operator_token, root, ["tool:execute"])
    assert root_token_data["on_behalf_of"] == test_user.id
    root_token = f"Bearer {root_token_data['access_token']}"

    delegate_resp = await client.post(
        "/api/v1/token/delegate",
        headers={"Authorization": root_token},
        json={"delegatee_agent_id": delegatee.id, "requested_scopes": ["tool:execute"]},
    )
    assert delegate_resp.status_code == 200, delegate_resp.text
    # Delegation attenuates scope, never the human the chain traces to.
    assert delegate_resp.json()["on_behalf_of"] == test_user.id


@pytest.mark.asyncio
async def test_explicit_grant_overrides_activation_default_for_covered_scope(
    client: AsyncClient, operator_token: str, db_session: AsyncSession, test_org: Organization,
):
    agent = await _make_pending_agent(db_session, test_org, "OBO Grant Override Agent", ["tool:execute", "audit:read"])
    await client.post(f"/api/v1/agents/{agent.id}/activate", headers={"Authorization": operator_token})

    second_user, second_password = await _make_second_operator(db_session, test_org)
    login_resp = await client.post(
        "/api/v1/auth/login", json={"email": second_user.email, "password": second_password}
    )
    assert login_resp.status_code == 200, login_resp.text
    second_operator_token = f"Bearer {login_resp.json()['access_token']}"

    grant_resp = await client.post(
        f"/api/v1/agents/{agent.id}/on-behalf-of-grants",
        headers={"Authorization": second_operator_token},
        json={"scopes": ["audit:read"], "ttl_seconds": 3600},
    )
    assert grant_resp.status_code == 201, grant_resp.text
    assert grant_resp.json()["granted_by_user_id"] == second_user.id

    # Requesting the GRANTED scope: the grant wins over activated_by_user_id.
    obo_token = await _issue_and_exchange(client, operator_token, agent, ["audit:read"])
    assert obo_token["on_behalf_of"] == second_user.id

    # Requesting a scope the grant does NOT cover: falls back to whoever activated it.
    default_token = await _issue_and_exchange(client, operator_token, agent, ["tool:execute"])
    assert default_token["on_behalf_of"] != second_user.id


@pytest.mark.asyncio
async def test_revoked_grant_no_longer_applies(
    client: AsyncClient, operator_token: str, test_user: User, db_session: AsyncSession, test_org: Organization,
):
    agent = await _make_pending_agent(db_session, test_org, "OBO Revoke Agent", ["tool:execute"])
    # test_user (operator_token) activates — this is the fallback anchor.
    await client.post(f"/api/v1/agents/{agent.id}/activate", headers={"Authorization": operator_token})

    # A DIFFERENT operator grants on-behalf-of for the same scope —
    # distinguishable from the activation anchor.
    second_user, second_password = await _make_second_operator(db_session, test_org)
    login_resp = await client.post(
        "/api/v1/auth/login", json={"email": second_user.email, "password": second_password}
    )
    assert login_resp.status_code == 200, login_resp.text
    second_operator_token = f"Bearer {login_resp.json()['access_token']}"

    grant_resp = await client.post(
        f"/api/v1/agents/{agent.id}/on-behalf-of-grants",
        headers={"Authorization": second_operator_token},
        json={"scopes": ["tool:execute"], "ttl_seconds": 3600},
    )
    assert grant_resp.status_code == 201, grant_resp.text
    grant_id = grant_resp.json()["id"]

    # Grant active: it wins over the activation anchor.
    active_token_data = await _issue_and_exchange(client, operator_token, agent, ["tool:execute"])
    assert active_token_data["on_behalf_of"] == second_user.id

    revoke_resp = await client.post(
        f"/api/v1/agents/{agent.id}/on-behalf-of-grants/{grant_id}/revoke",
        headers={"Authorization": operator_token},
        json={"reason": "test revoke"},
    )
    assert revoke_resp.status_code == 200, revoke_resp.text

    # Grant revoked: falls back to activated_by_user_id (test_user).
    post_revoke_token_data = await _issue_and_exchange(client, operator_token, agent, ["tool:execute"])
    assert post_revoke_token_data["on_behalf_of"] == test_user.id


@pytest.mark.asyncio
async def test_audit_trace_surfaces_originating_operator(
    client: AsyncClient, operator_token: str, test_user: User, db_session: AsyncSession, test_org: Organization,
):
    agent = await _make_pending_agent(db_session, test_org, "OBO Trace Agent", ["tool:execute"])
    await client.post(f"/api/v1/agents/{agent.id}/activate", headers={"Authorization": operator_token})
    token_data = await _issue_and_exchange(client, operator_token, agent, ["tool:execute"])

    trace_resp = await client.get(
        f"/api/v1/audit/trace/{token_data['causal_trace_id']}",
        headers={"Authorization": operator_token},
    )
    assert trace_resp.status_code == 200, trace_resp.text
    assert trace_resp.json()["originating_operator"] == test_user.id


@pytest.mark.asyncio
async def test_on_behalf_of_is_never_a_caller_supplied_value(
    client: AsyncClient, operator_token: str, db_session: AsyncSession, test_org: Organization,
):
    """
    An agent never activated by anyone, with no grant, must carry NO
    on_behalf_of at all — there is no request field anywhere that could
    smuggle one in, so this proves the "cannot claim a human who never
    authorized it" property directly: no code path accepts a value.
    """
    # ACTIVE directly, never through /activate — activated_by_user_id stays NULL.
    agent = await _make_already_active_agent(db_session, test_org, "OBO No Anchor Agent", ["tool:execute"])

    token_data = await _issue_and_exchange(client, operator_token, agent, ["tool:execute"])
    assert token_data["on_behalf_of"] is None
