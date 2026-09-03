"""
Automated tests for zero-downtime API key rotation.
Verifies grace window dual-key acceptance (`verify_key`) and post-grace rejection.
"""

import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.organization import Organization
from app.models.agent import Agent
from app.services.api_key_service import api_key_service


@pytest.mark.asyncio
async def test_zero_downtime_key_rotation_grace_window(
    db_session: AsyncSession, test_org: Organization, test_agent: Agent
):
    """Verifies that rotating an API key allows both old and new keys during grace period."""
    # 1. Issue initial API key
    issue_res = await api_key_service.issue_key(
        db_session,
        agent_id=test_agent.id,
        org_id=test_org.id,
        scopes=["audit:read"],
        actor_id="admin",
    )
    old_plaintext = issue_res["plaintext_key"]
    old_key_id = issue_res["key_id"]

    # Verify old key works before rotation
    verify_old = await api_key_service.verify_key(
        db_session,
        plaintext_key=old_plaintext,
        org_id=test_org.id,
        causal_trace_id="test-1",
    )
    assert verify_old is not None
    assert verify_old["key_id"] == old_key_id
    assert verify_old["using_grace_key"] is False

    # 2. Rotate key with 2 hour grace period
    rotate_res = await api_key_service.rotate_key(
        db_session,
        key_id=old_key_id,
        org_id=test_org.id,
        actor_id="admin",
        grace_period_hours=2,
    )
    new_plaintext = rotate_res["plaintext_key"]
    new_key_id = rotate_res["key_id"]

    # 3. Verify BOTH keys work right now
    verify_new = await api_key_service.verify_key(
        db_session,
        plaintext_key=new_plaintext,
        org_id=test_org.id,
        causal_trace_id="test-2",
    )
    assert verify_new is not None
    assert verify_new["key_id"] == new_key_id
    assert verify_new["using_grace_key"] is False

    verify_grace = await api_key_service.verify_key(
        db_session,
        plaintext_key=old_plaintext,
        org_id=test_org.id,
        causal_trace_id="test-3",
    )
    assert verify_grace is not None
    assert verify_grace["key_id"] == new_key_id
    assert verify_grace["using_grace_key"] is True

    # 4. Simulate expiration of grace window on the new key record in DB
    from sqlalchemy import update
    from app.models.api_key import ApiKey
    await db_session.execute(
        update(ApiKey)
        .where(ApiKey.key_id == new_key_id)
        .values(previous_key_expires_at=datetime.now(timezone.utc) - timedelta(minutes=5))
    )
    await db_session.commit()

    # Now verify old key is rejected
    verify_expired = await api_key_service.verify_key(
        db_session,
        plaintext_key=old_plaintext,
        org_id=test_org.id,
        causal_trace_id="test-4",
    )
    assert verify_expired is None
