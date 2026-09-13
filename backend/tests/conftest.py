"""
Pytest fixtures and configuration for AI-IAM Platform.
Sets up an async PostgreSQL test database session, FastAPI TestClient,
and seeded operator / organization / agent fixtures.

Postgres, not SQLite: the schema uses JSONB/ARRAY columns and the audit
hash-chain's concurrency guarantee is a `SELECT ... FOR UPDATE` on
Postgres. None of that is expressible on SQLite, so testing there would
certify a chain implementation without ever exercising its one
concurrency guarantee. See docs/testing.md for how to stand up the
test database locally and in CI.
"""

import os
import uuid
import pytest_asyncio
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.db.session import get_db
from app.models.base import Base
from app.models.organization import Organization
from app.models.user import User
from app.models.agent import Agent
from app.core.constants import AgentStatus

# Dedicated test database — never the dev database, so a dropped table
# here can't take out anything a developer is looking at. Override with
# TEST_DATABASE_URL to point at a CI service or a different local port.
TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://aiiam_user:supersecretpassword@localhost:5432/aiiam_test_db",
)

# NullPool: every checkout is a genuinely fresh asyncpg connection, never
# reused from a pool. Each test's db_session fixture does create_all at
# setup and drop_all at teardown against this same module-level engine —
# with a reused connection pool, a connection left in an unexpected state
# by one test (an uncommitted transaction, a cursor mid-flight) can
# surface as an unrelated failure in a completely different test's
# fixture setup ("another operation is in progress"). alembic/env.py
# already uses NullPool for the same reason.
test_engine = create_async_engine(TEST_DATABASE_URL, echo=False, poolclass=NullPool)
TestingSessionLocal = async_sessionmaker(
    bind=test_engine, class_=AsyncSession, expire_on_commit=False
)


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Create a fresh database session for a test and drop tables after cleanup."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestingSessionLocal() as session:
        yield session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(scope="function")
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Provide an AsyncClient instance overriding the get_db dependency."""
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest_asyncio.fixture(scope="function")
async def test_org(db_session: AsyncSession) -> Organization:
    """Create and return a sample organization fixture."""
    org = Organization(
        id=str(uuid.uuid4()),
        name="Test Corp AI",
        slug="test-corp-ai",
        is_active=True,
    )
    db_session.add(org)
    await db_session.commit()
    await db_session.refresh(org)
    return org


@pytest_asyncio.fixture(scope="function")
async def test_user(db_session: AsyncSession, test_org: Organization) -> User:
    """Create and return a sample active operator user."""
    import bcrypt
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(b"SecretPassword123!", salt).decode()
    user = User(
        id=str(uuid.uuid4()),
        org_id=test_org.id,
        email="operator@testcorp.ai",
        hashed_password=hashed,
        is_active=True,
        is_superuser=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture(scope="function")
async def operator_token(client: AsyncClient, test_user: User) -> str:
    """Return a valid operator Authorization token string."""
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "operator@testcorp.ai", "password": "SecretPassword123!"},
    )
    assert response.status_code == 200
    data = response.json()
    return f"Bearer {data['access_token']}"


@pytest_asyncio.fixture(scope="function")
async def test_agent(db_session: AsyncSession, test_org: Organization) -> Agent:
    """Create and return a sample ACTIVE AI agent fixture."""
    agent = Agent(
        id=str(uuid.uuid4()),
        org_id=test_org.id,
        name="Security Sentinel Agent",
        description="Autonomous threat monitoring agent",
        status=AgentStatus.ACTIVE,
        spiffe_id=f"spiffe://ai-iam.internal/ns/{test_org.id}/sa/security-sentinel",
        allowed_scopes=["audit:read", "threat:mitigate", "tool:execute"],
        mcp_bindings=[
            {"server_id": "srv-1", "server_url": "http://mock-mcp:8080", "tool_filter": ["search_web"]},
        ],
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent
