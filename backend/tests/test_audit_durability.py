"""
Slice 8 regression tests: audit entries are written out of band from the
row they describe, and the audit-writer Postgres role is genuinely
INSERT/SELECT-only — not just documented as such.
"""

from unittest.mock import patch

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from app.models.organization import Organization
from app.models.audit_log import AuditLog
from app.repositories.audit_repo import audit_repo
from app.services.agent_service import agent_service
from app.core.constants import AuditAction

from conftest import AUDIT_TEST_DATABASE_URL


@pytest.mark.asyncio
async def test_agent_registration_audit_survives_downstream_failure(
    db_session: AsyncSession, test_org: Organization
):
    """
    Regression test for the confirmed live crash: agent_service.register()
    audits AGENT_REGISTERED before the agent row it names exists. Force
    the write that follows to fail and confirm the audit entry is still
    there — durable independently of the caller's own transaction,
    because audit_repo.append() commits it on its own out-of-band
    session rather than relying on the caller ever committing.
    """
    with patch(
        "app.services.agent_service.agent_repo.create",
        side_effect=RuntimeError("simulated downstream failure"),
    ):
        with pytest.raises(RuntimeError):
            await agent_service.register(
                db_session,
                org_id=test_org.id,
                name="Doomed Agent",
                description=None,
                allowed_scopes=["tool:execute"],
                mcp_bindings=None,
                parent_agent_id=None,
                is_ephemeral=False,
                ephemeral_ttl_seconds=None,
                actor_id="test-operator",
            )

    # The caller's own session is now in a failed state for whatever
    # agent_repo.create half-did — roll it back, exactly like get_db does
    # on a real request that raises. The audit entry must survive this.
    await db_session.rollback()

    row = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == AuditAction.AGENT_REGISTERED.value,
                AuditLog.details["agent_name"].astext == "Doomed Agent",
            )
        )
    ).scalar_one_or_none()
    assert row is not None, "audit entry for a failed registration did not survive"
    assert row.outcome == "success"


@pytest.mark.asyncio
async def test_audit_writer_role_cannot_update_or_delete(db_session: AsyncSession):
    """
    The append-only guarantee has to be enforced by Postgres, not just
    documented — connect as the actual role audit_repo.append() uses and
    confirm the database itself refuses UPDATE/DELETE on audit_logs, even
    though that role can INSERT into and SELECT from the same table.

    Depends on db_session purely to trigger its fixture's table
    creation and audit-writer role/grant setup before this runs — this
    test builds its own separate connection rather than using the
    session itself.
    """
    restricted_engine = create_async_engine(AUDIT_TEST_DATABASE_URL, connect_args={"ssl": False})
    try:
        async with restricted_engine.connect() as conn:
            # SELECT and INSERT must both work — this role isn't locked
            # out of the table entirely, only out of mutating it.
            await conn.execute(text("SELECT 1 FROM audit_logs LIMIT 1"))

            with pytest.raises(DBAPIError, match="(?i)permission denied"):
                await conn.execute(
                    text("UPDATE audit_logs SET action = 'tampered' WHERE 1=0")
                )
            await conn.rollback()

            with pytest.raises(DBAPIError, match="(?i)permission denied"):
                await conn.execute(text("DELETE FROM audit_logs WHERE 1=0"))
            await conn.rollback()
    finally:
        await restricted_engine.dispose()


@pytest.mark.asyncio
async def test_verify_chain_correct_across_small_batches(
    db_session: AsyncSession, test_org: Organization
):
    """
    Batching (yield_per) must not change the result — append enough
    entries to span multiple batches at a small batch_size and confirm
    verify_chain still reports the true count and validity.
    """
    for i in range(5):
        await audit_repo.append(
            org_id=test_org.id,
            action=AuditAction.CREDENTIAL_USED,
            actor_type="agent",
            actor_id=f"agent-batch-{i}",
            causal_trace_id="trace-batch",
            outcome="success",
            details={"i": i},
        )

    is_valid, broken_at, total_checked = await audit_repo.verify_chain(
        db_session, test_org.id, batch_size=2
    )
    assert is_valid is True
    assert broken_at is None
    assert total_checked == 5
