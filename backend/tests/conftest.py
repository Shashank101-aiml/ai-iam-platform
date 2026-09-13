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
from sqlalchemy.engine import make_url

# Dedicated test database — never the dev database, so a dropped table
# here can't take out anything a developer is looking at. Override with
# TEST_DATABASE_URL to point at a CI service or a different local port.
#
# This has to be computed, and AUDIT_DATABASE_URL has to be set, BEFORE
# `from app.main import app` below — that import chain constructs
# app.core.config.settings and app.db.session's audit_engine at module
# load time, reading AUDIT_DATABASE_URL from the environment right then.
# Set it any later and the audit writer would silently connect to the
# dev database instead of the test one (see app/repositories/audit_repo.py
# and app/db/session.py — audit_repo.append() no longer takes the
# caller's db session at all, precisely so it can't be pointed at the
# wrong database by a fixture override the way get_db can be).
TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://aiiam_user:supersecretpassword@localhost:5432/aiiam_test_db",
)
# Same database, the actual least-privileged audit-writer role (see
# migration 0003_audit_log_durability) — proves the real restricted role
# during tests instead of bypassing it.
#
# render_as_string(hide_password=False) — NOT str(...)/repr(...), which
# SQLAlchemy's URL masks to a literal "***" by default. Building this
# with plain str() silently produces a connection string whose password
# really is the three characters "***", which then fails authentication
# against Postgres with no indication why (cost real debugging time to
# track down — asyncpg's error just says "password authentication
# failed", not "you passed the placeholder mask instead of a password").
AUDIT_TEST_DATABASE_URL = make_url(TEST_DATABASE_URL).set(
    username="aiiam_audit_writer", password="audit_writer_dev_password"
).render_as_string(hide_password=False)
os.environ.setdefault("AUDIT_DATABASE_URL", AUDIT_TEST_DATABASE_URL)

# Revocation index (app/core/revocation.py) — a different Redis DB index
# than the dev default (0), not a different instance, so a fresh
# `redis:7-alpine` isn't required just for tests. Same ordering
# constraint as AUDIT_DATABASE_URL above: settings.REDIS_URL is read at
# first import of app.core.config, which `from app.main import app`
# below triggers — set this before that line, not after.
TEST_REDIS_URL = os.environ.get("TEST_REDIS_URL", "redis://localhost:6379/1")
os.environ.setdefault("REDIS_URL", TEST_REDIS_URL)

import pytest_asyncio
from typing import AsyncGenerator
from sqlalchemy import text
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


@pytest_asyncio.fixture(scope="function", autouse=True)
async def _flush_test_redis() -> AsyncGenerator[None, None]:
    """
    Isolate every test's revocation-index state. Flushes only the ONE
    test-dedicated Redis DB (see TEST_REDIS_URL above) — never touches
    whatever DB index a dev/prod deployment would actually use.
    """
    from app.core.revocation import get_redis_client, reset_redis_client

    await reset_redis_client()
    client = get_redis_client()
    await client.flushdb()
    yield
    await client.flushdb()
    await reset_redis_client()


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Create a fresh database session for a test and drop tables after cleanup."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Tests build the schema directly from the models (create_all),
        # never via `alembic upgrade head` — so migration
        # 0003_audit_log_durability's role/grant SQL never runs here.
        # Recreate the same least-privileged audit-writer role by hand so
        # tests exercise the real restricted role (audit_repo.append()
        # connects as it — see AUDIT_TEST_DATABASE_URL above) instead of
        # silently skipping that guarantee. CREATE ROLE is cluster-wide,
        # not per-database, so this only actually runs once per Postgres
        # instance — idempotent by design, not just by accident.
        # ALTERs the password every time rather than skipping when the
        # role already exists — this role is cluster-wide (CREATE ROLE
        # isn't scoped to a database) and persists across container
        # restarts via the Postgres data volume, so a stale password from
        # some earlier state must not be able to silently outlive this.
        await conn.execute(text("""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'aiiam_audit_writer') THEN
                    CREATE ROLE aiiam_audit_writer LOGIN PASSWORD 'audit_writer_dev_password';
                ELSE
                    ALTER ROLE aiiam_audit_writer LOGIN PASSWORD 'audit_writer_dev_password';
                END IF;
            END
            $$;
        """))
        db_name = (await conn.execute(text("SELECT current_database()"))).scalar()
        await conn.execute(text(f'GRANT CONNECT ON DATABASE "{db_name}" TO aiiam_audit_writer'))
        await conn.execute(text("GRANT USAGE ON SCHEMA public TO aiiam_audit_writer"))
        await conn.execute(text("GRANT INSERT, SELECT ON audit_logs TO aiiam_audit_writer"))

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
