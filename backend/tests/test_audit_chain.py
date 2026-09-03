"""
Automated tests for SHA256 append-only audit hash chain.
Verifies cryptographic sequence linking (`previous_hash`) and tamper detection alerts.
"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.models.organization import Organization
from app.repositories.audit_repo import audit_repo
from app.core.constants import AuditAction


@pytest.mark.asyncio
async def test_audit_chain_links_sequentially_and_verifies(
    db_session: AsyncSession, test_org: Organization
):
    """Verifies that multiple appended audit entries maintain sequential hash integrity."""
    # Append event 1
    ev1 = await audit_repo.append(
        db_session,
        org_id=test_org.id,
        action=AuditAction.AGENT_REGISTERED,
        actor_type="user",
        actor_id="admin-user",
        agent_id="agent-101",
        causal_trace_id="trace-001",
        outcome="success",
        details={"step": 1},
    )
    assert ev1.sequence_number == 1
    assert ev1.previous_hash == "0" * 64
    assert len(ev1.entry_hash) == 64

    # Append event 2
    ev2 = await audit_repo.append(
        db_session,
        org_id=test_org.id,
        action=AuditAction.AGENT_ACTIVATED,
        actor_type="user",
        actor_id="admin-user",
        agent_id="agent-101",
        causal_trace_id="trace-001",
        outcome="success",
        details={"step": 2},
    )
    assert ev2.sequence_number == 2
    assert ev2.previous_hash == ev1.entry_hash

    # Verify chain validity
    is_valid, broken_at = await audit_repo.verify_chain(db_session, test_org.id)
    assert is_valid is True
    assert broken_at is None


@pytest.mark.asyncio
async def test_tamper_detection_alerts_on_broken_chain(
    db_session: AsyncSession, test_org: Organization
):
    """Verifies that altering an entry hash breaks the chain and flags exact sequence."""
    # Append two events
    await audit_repo.append(
        db_session,
        org_id=test_org.id,
        action=AuditAction.CREDENTIAL_ISSUED,
        actor_type="user",
        actor_id="admin-user",
        agent_id="agent-202",
        causal_trace_id="trace-002",
        outcome="success",
    )
    ev2 = await audit_repo.append(
        db_session,
        org_id=test_org.id,
        action=AuditAction.CREDENTIAL_ROTATED,
        actor_type="user",
        actor_id="admin-user",
        agent_id="agent-202",
        causal_trace_id="trace-002",
        outcome="success",
    )

    # Simulate SQL injection / database tamper by manually updating entry 1's action
    # without updating the hash or subsequent links
    await db_session.execute(
        text("UPDATE audit_logs SET action = 'tampered_action' WHERE sequence_number = 1")
    )
    await db_session.commit()

    # Run verification check
    is_valid, broken_at = await audit_repo.verify_chain(db_session, test_org.id)
    assert is_valid is False
    assert broken_at == 1
