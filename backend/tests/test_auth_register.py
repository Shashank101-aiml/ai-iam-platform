"""
POST /auth/register requires an authenticated operator.

It used to take no authentication at all: anyone who knew an organization's
UUID (they appear in SPIFFE ids, tokens and audit details) could add
themselves as an operator of that org and take over its agents and keys. A
regular operator may now only add users to their own org; a superuser may
name any org.
"""

import uuid

import bcrypt
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.organization import Organization
from app.models.user import User

PASSWORD = "OperatorPass123!"


async def _operator(db: AsyncSession, org: Organization, email: str, *, superuser: bool = False) -> User:
    user = User(
        id=str(uuid.uuid4()),
        org_id=org.id,
        email=email,
        hashed_password=bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt(rounds=4)).decode(),
        is_active=True,
        is_superuser=superuser,
    )
    db.add(user)
    await db.commit()
    return user


NEW_USER_PASSWORD = "NewUserPass123!"


async def _login(client: AsyncClient, email: str, password: str = PASSWORD) -> dict:
    response = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def _other_org(db: AsyncSession) -> Organization:
    org = Organization(id=str(uuid.uuid4()), name="Other Corp", slug="other-corp", is_active=True)
    db.add(org)
    await db.commit()
    return org


def _body(org_id: str, email: str, **extra) -> dict:
    return {"org_id": org_id, "email": email, "password": NEW_USER_PASSWORD, **extra}


async def _user_by_email(db: AsyncSession, email: str):
    return (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()


@pytest.mark.asyncio
async def test_register_requires_authentication(
    client: AsyncClient, db_session: AsyncSession, test_org: Organization
):
    response = await client.post("/api/v1/auth/register", json=_body(test_org.id, "intruder@evil.example"))
    assert response.status_code == 401
    assert await _user_by_email(db_session, "intruder@evil.example") is None


@pytest.mark.asyncio
async def test_operator_can_add_an_operator_to_their_own_org(
    client: AsyncClient, db_session: AsyncSession, test_org: Organization
):
    await _operator(db_session, test_org, "regular@testcorp.ai")
    headers = await _login(client, "regular@testcorp.ai")

    response = await client.post(
        "/api/v1/auth/register", headers=headers, json=_body(test_org.id, "teammate@testcorp.ai")
    )
    assert response.status_code == 201, response.text
    assert response.json()["org_id"] == test_org.id
    assert response.json()["is_superuser"] is False
    await _login(client, "teammate@testcorp.ai", NEW_USER_PASSWORD)  # and the new account really works


@pytest.mark.asyncio
async def test_operator_cannot_register_into_another_org_and_it_looks_like_a_missing_org(
    client: AsyncClient, db_session: AsyncSession, test_org: Organization
):
    other = await _other_org(db_session)
    await _operator(db_session, test_org, "regular@testcorp.ai")
    headers = await _login(client, "regular@testcorp.ai")

    foreign = await client.post("/api/v1/auth/register", headers=headers, json=_body(other.id, "planted@other.example"))
    missing = await client.post(
        "/api/v1/auth/register", headers=headers, json=_body(str(uuid.uuid4()), "planted2@other.example")
    )

    assert foreign.status_code == 404
    # Same status and body as a nonexistent org: a 403 would confirm the id is valid.
    assert (foreign.status_code, foreign.json()) == (missing.status_code, missing.json())
    assert await _user_by_email(db_session, "planted@other.example") is None


@pytest.mark.asyncio
async def test_is_superuser_in_the_body_is_ignored(
    client: AsyncClient, db_session: AsyncSession, test_org: Organization
):
    await _operator(db_session, test_org, "regular@testcorp.ai")
    headers = await _login(client, "regular@testcorp.ai")

    response = await client.post(
        "/api/v1/auth/register", headers=headers,
        json=_body(test_org.id, "wannabe@testcorp.ai", is_superuser=True),
    )
    assert response.status_code == 201, response.text
    assert response.json()["is_superuser"] is False
    assert (await _user_by_email(db_session, "wannabe@testcorp.ai")).is_superuser is False


@pytest.mark.asyncio
async def test_superuser_can_register_into_any_org_but_a_bogus_org_is_404_not_500(
    client: AsyncClient, db_session: AsyncSession, test_org: Organization, operator_token: str
):
    # operator_token is the conftest superuser's token.
    other = await _other_org(db_session)
    headers = {"Authorization": operator_token}

    ok = await client.post("/api/v1/auth/register", headers=headers, json=_body(other.id, "admin@other.example"))
    assert ok.status_code == 201, ok.text
    assert ok.json()["org_id"] == other.id

    bogus = await client.post(
        "/api/v1/auth/register", headers=headers, json=_body(str(uuid.uuid4()), "ghost@other.example")
    )
    assert bogus.status_code == 404
