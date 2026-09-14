"""
Slice 15 test: Postgres advisory-lock helper for singleton background work.

Directly exercises try_acquire() — the mechanism credential_rotator.py
and audit_verifier.py now use so that only ONE of several worker
processes actually performs a scheduled cycle's work (this project's
own Dockerfile CMD runs 4 uvicorn workers, each starting its own copy
of every background loop with no other coordination). Two separate
sessions here simulate two separate worker processes racing for the
same lock name.
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from conftest import TestingSessionLocal
from app.core.worker_lock import try_acquire


@pytest.mark.asyncio
async def test_only_one_of_two_concurrent_sessions_acquires_the_same_lock(db_session: AsyncSession):
    async with TestingSessionLocal() as other_session:
        assert await try_acquire(db_session, "test-lock-name") is True
        assert await try_acquire(other_session, "test-lock-name") is False, (
            "a second session must not acquire a lock the first still holds"
        )
        await other_session.rollback()

    await db_session.commit()  # releases db_session's lock


@pytest.mark.asyncio
async def test_lock_is_released_after_commit_and_reacquirable(db_session: AsyncSession):
    assert await try_acquire(db_session, "test-lock-reacquire") is True
    await db_session.commit()  # releases it

    async with TestingSessionLocal() as other_session:
        assert await try_acquire(other_session, "test-lock-reacquire") is True
        await other_session.commit()


@pytest.mark.asyncio
async def test_different_lock_names_dont_contend(db_session: AsyncSession):
    async with TestingSessionLocal() as other_session:
        assert await try_acquire(db_session, "test-lock-a") is True
        assert await try_acquire(other_session, "test-lock-b") is True
        await other_session.commit()

    await db_session.commit()
