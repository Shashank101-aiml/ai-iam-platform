"""
Tenant isolation tests.

Confirms a regular (non-superuser) operator in one org can never observe
another org's organization record, agents, or API key metadata by
guessing/enumerating IDs — every cross-tenant lookup returns 404, never
403. A 403 would confirm the resource exists and access is merely
denied; a 404 gives nothing away about whether it exists at all.

Uses its own org_a/org_b/operator_a/operator_b fixtures rather than
conftest.py's test_org/test_user — that shared operator is deliberately
is_superuser=True (used elsewhere as the general-purpose authenticated
operator), and superusers are the intended, designed exception to org
scoping on the organizations endpoints. Testing isolation with a
superuser would test the wrong thing.
"""

import uuid

import bcrypt
import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.organization import Organization
from app.models.user import User
from app.models.agent import Agent
from app.core.constants import AgentStatus


async def _create_operator(
    db_session: AsyncSession, org: Organization, email: str, password: str
) -> User:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt).decode()
    user = User(
        id=str(uuid.uuid4()),
        org_id=org.id,
        email=email,
        hashed_password=hashed,
        is_active=True,
        is_superuser=False,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


async def _login(client: AsyncClient, email: str, password: str) -> str:
    response = await client.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )
    assert response.status_code == 200, response.text
    return f"Bearer {response.json()['access_token']}"


@pytest_asyncio.fixture
async def org_a(db_session: AsyncSession) -> Organization:
    org = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a", is_active=True)
    db_session.add(org)
    await db_session.commit()
    await db_session.refresh(org)
    return org


@pytest_asyncio.fixture
async def org_b(db_session: AsyncSession) -> Organization:
    org = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b", is_active=True)
    db_session.add(org)
    await db_session.commit()
    await db_session.refresh(org)
    return org


@pytest_asyncio.fixture
async def operator_a(db_session: AsyncSession, org_a: Organization) -> User:
    return await _create_operator(db_session, org_a, "operator-a@example.com", "PasswordA123!")


@pytest_asyncio.fixture
async def operator_b(db_session: AsyncSession, org_b: Organization) -> User:
    return await _create_operator(db_session, org_b, "operator-b@example.com", "PasswordB123!")


@pytest_asyncio.fixture
async def agent_b(db_session: AsyncSession, org_b: Organization) -> Agent:
    """An ACTIVE agent belonging to org B — operator A must never see it."""
    agent = Agent(
        id=str(uuid.uuid4()),
        org_id=org_b.id,
        name="Org B's Agent",
        status=AgentStatus.ACTIVE,
        allowed_scopes=["tool:execute"],
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


@pytest.mark.asyncio
async def test_operator_cannot_read_other_orgs_organization(
    client: AsyncClient, operator_a: User, org_b: Organization
):
    token = await _login(client, "operator-a@example.com", "PasswordA123!")
    response = await client.get(
        f"/api/v1/organizations/{org_b.id}", headers={"Authorization": token}
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_list_organizations_only_shows_own_org(
    client: AsyncClient, operator_a: User, org_a: Organization, org_b: Organization
):
    token = await _login(client, "operator-a@example.com", "PasswordA123!")
    response = await client.get(
        "/api/v1/organizations", headers={"Authorization": token}
    )
    assert response.status_code == 200
    org_ids = {o["id"] for o in response.json()}
    assert org_ids == {org_a.id}


@pytest.mark.asyncio
async def test_regular_operator_cannot_create_organization(
    client: AsyncClient, operator_a: User
):
    """Org creation is a superuser-only action (get_current_superuser)."""
    token = await _login(client, "operator-a@example.com", "PasswordA123!")
    response = await client.post(
        "/api/v1/organizations",
        headers={"Authorization": token},
        json={"name": "Unauthorized New Org", "slug": "unauthorized-new-org"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_superuser_can_read_other_orgs_organization(
    client: AsyncClient, operator_token: str, org_b: Organization
):
    """The escape hatch: cross-org reads are for superusers, not disabled entirely."""
    response = await client.get(
        f"/api/v1/organizations/{org_b.id}", headers={"Authorization": operator_token}
    )
    assert response.status_code == 200
    assert response.json()["id"] == org_b.id


@pytest.mark.asyncio
async def test_operator_cannot_read_other_orgs_agent(
    client: AsyncClient, operator_a: User, agent_b: Agent
):
    token = await _login(client, "operator-a@example.com", "PasswordA123!")
    response = await client.get(
        f"/api/v1/agents/{agent_b.id}", headers={"Authorization": token}
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_operator_cannot_list_other_orgs_agent_keys(
    client: AsyncClient, operator_a: User, agent_b: Agent
):
    token = await _login(client, "operator-a@example.com", "PasswordA123!")
    response = await client.get(
        f"/api/v1/agents/{agent_b.id}/keys", headers={"Authorization": token}
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_operator_cannot_issue_key_for_other_orgs_agent(
    client: AsyncClient, operator_a: User, agent_b: Agent
):
    token = await _login(client, "operator-a@example.com", "PasswordA123!")
    response = await client.post(
        f"/api/v1/agents/{agent_b.id}/keys",
        headers={"Authorization": token},
        json={"scopes": ["tool:execute"], "ttl_days": 30},
    )
    assert response.status_code == 404
