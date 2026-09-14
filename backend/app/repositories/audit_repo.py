"""
Audit Log Repository — the most security-critical repo.

Enforces two guarantees that no other layer should be able to bypass:

1. APPEND-ONLY: This repo has NO update() or delete() methods, and
   append() connects as its own dedicated Postgres role (see
   app/db/session.py's audit_engine and migration
   0003_audit_log_durability) that holds INSERT + SELECT on audit_logs
   and NOTHING else — no UPDATE, no DELETE, enforced by Postgres itself,
   not just by this class's method set.

2. HASH CHAIN INTEGRITY: Every append() call reads the last entry's
   hash and chains the new entry to it, serialized against concurrent
   appends for the same org via a Postgres advisory transaction lock
   (see _get_chain_tip) rather than SELECT ... FOR UPDATE, which would
   need the UPDATE privilege this role deliberately doesn't have.
"""

import json
from typing import Optional, Sequence

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.core.security import compute_entry_hash, AUDIT_CHAIN_GENESIS
from app.core.constants import AuditAction
from app.core.config import settings
from app.core.metrics import AUDIT_CHAIN_VERIFY_DURATION_SECONDS
from app.db.session import AuditSessionLocal
from app.repositories.base_repo import BaseRepository


class AuditRepository(BaseRepository[AuditLog]):
    def __init__(self):
        super().__init__(AuditLog)

    async def append(
        self,
        *,
        org_id: str,
        action: AuditAction,
        actor_type: str,
        actor_id: str,
        causal_trace_id: str,
        outcome: str,
        agent_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[dict] = None,
        parent_event_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuditLog:
        """
        Append a new entry to the audit chain — OUT OF BAND from whatever
        transaction the caller is in.

        Deliberately does NOT take the caller's db session. This opens
        its OWN session against AuditSessionLocal, connected as a
        Postgres role that can only INSERT/SELECT on audit_logs (see
        migration 0003_audit_log_durability) and commits immediately.
        Two consequences, both intentional:

        1. An audit entry survives independently of whatever the caller's
           own transaction does next. agent_service.register() audits
           AGENT_REGISTERED before the agent row it names exists — if
           that later insert fails or the caller's transaction never
           commits for an unrelated reason, the audit entry is already
           durable.
        2. Even a fully compromised app role — one that could otherwise
           run arbitrary SQL through the app's normal connection — can't
           use this code path to tamper with or erase an existing entry,
           because the role it authenticates as is physically incapable
           of UPDATE/DELETE on this table.

        Atomically, within its own session:
        1. Locks the last entry for this org (SELECT FOR UPDATE)
        2. Reads its hash and sequence number
        3. Computes the new entry's hash = SHA256(content + prev_hash)
        4. Inserts and commits the new entry
        """
        async with AuditSessionLocal() as db:
            # Step 1: Get the previous entry for chain continuity
            prev_hash, next_seq = await self._get_chain_tip(db, org_id)

            # Step 2: Build the canonical content string for hashing
            # Must be deterministic — same inputs always produce same hash
            content = json.dumps({
                "org_id": org_id,
                "action": action.value,
                "actor_id": actor_id,
                "causal_trace_id": causal_trace_id,
                "outcome": outcome,
                "sequence_number": next_seq,
                "details": details or {},
            }, sort_keys=True)  # sort_keys=True ensures deterministic ordering

            # Step 3: Compute hash linking this entry to the chain
            entry_hash = compute_entry_hash(content, prev_hash)

            # Step 4: Create, persist, and commit the entry
            entry = AuditLog(
                org_id=org_id,
                agent_id=agent_id,
                action=action.value,
                details=details,
                actor_type=actor_type,
                actor_id=actor_id,
                resource_type=resource_type,
                resource_id=resource_id,
                outcome=outcome,
                causal_trace_id=causal_trace_id,
                parent_event_id=parent_event_id,
                entry_hash=entry_hash,
                previous_hash=prev_hash,
                sequence_number=next_seq,
                source_ip=source_ip,
                user_agent=user_agent,
            )
            db.add(entry)
            await db.commit()
            await db.refresh(entry)
            return entry

    async def _get_chain_tip(
        self, db: AsyncSession, org_id: str
    ) -> tuple[str, int]:
        """
        Get the last entry's hash and next sequence number for this org.

        Serializes concurrent appends for the SAME org with a Postgres
        advisory transaction lock keyed by org_id, not a `SELECT ... FOR
        UPDATE`. FOR UPDATE would work too, but Postgres requires the
        UPDATE privilege on the table to take that lock even though
        nothing is actually being updated — which would mean granting
        the audit-writer role UPDATE just to let it serialize its own
        reads, defeating the entire point of a role that can only
        INSERT/SELECT (see migration 0003_audit_log_durability). An
        advisory lock needs no table privilege at all: it's scoped to
        the current transaction and releases automatically on commit —
        exactly the lifetime of one append() call.
        """
        await db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:org_id)::bigint)"), {"org_id": org_id})

        result = await db.execute(
            select(AuditLog.entry_hash, AuditLog.sequence_number)
            .where(AuditLog.org_id == org_id)
            .order_by(AuditLog.sequence_number.desc())
            .limit(1)
        )
        row = result.one_or_none()
        if row is None:
            # First entry for this org — start the genesis chain
            return AUDIT_CHAIN_GENESIS, 1
        return row.entry_hash, row.sequence_number + 1

    async def verify_chain(
        self, db: AsyncSession, org_id: str, batch_size: Optional[int] = None
    ) -> tuple[bool, Optional[int], int]:
        """
        Replay the entire audit chain for an org and verify integrity.

        Returns (is_valid, broken_at_sequence_number, total_entries_checked).
        If valid: (True, None, count)
        If tampered: (False, sequence_number_of_first_broken_link, count_checked_before_the_break)

        Streams the chain in batches of `batch_size` (default
        settings.AUDIT_VERIFY_BATCH_SIZE) rather than loading a whole
        org's history into memory at once — this is what lets a periodic
        verification job (see worker/audit_verifier.py) run against an
        org with millions of entries in fixed memory instead of however
        much RAM the full result set happens to need.

        The whole call is timed into AUDIT_CHAIN_VERIFY_DURATION_SECONDS
        (Slice 14) — one instrumentation point covers both the periodic
        worker and the on-demand GET /audit/verify endpoint, since both
        call this same method rather than duplicating the replay logic.
        """
        with AUDIT_CHAIN_VERIFY_DURATION_SECONDS.time():
            batch_size = batch_size or settings.AUDIT_VERIFY_BATCH_SIZE
            stmt = (
                select(AuditLog)
                .where(AuditLog.org_id == org_id)
                .order_by(AuditLog.sequence_number.asc())
                .execution_options(yield_per=batch_size)
            )

            prev_hash = AUDIT_CHAIN_GENESIS
            checked = 0
            result = await db.stream_scalars(stmt)
            async for entry in result:
                content = json.dumps({
                    "org_id": entry.org_id,
                    "action": entry.action,
                    "actor_id": entry.actor_id,
                    "causal_trace_id": entry.causal_trace_id,
                    "outcome": entry.outcome,
                    "sequence_number": entry.sequence_number,
                    "details": entry.details or {},
                }, sort_keys=True)

                expected_hash = compute_entry_hash(content, prev_hash)
                checked += 1
                if expected_hash != entry.entry_hash:
                    return False, entry.sequence_number, checked

                prev_hash = entry.entry_hash

            return True, None, checked

    async def get_by_trace(
        self, db: AsyncSession, causal_trace_id: str, org_id: str
    ) -> Sequence[AuditLog]:
        """Return all events belonging to one causal trace chain."""
        result = await db.execute(
            select(AuditLog)
            .where(
                AuditLog.causal_trace_id == causal_trace_id,
                AuditLog.org_id == org_id,
            )
            .order_by(AuditLog.sequence_number.asc())
        )
        return result.scalars().all()

    async def get_by_agent(
        self,
        db: AsyncSession,
        agent_id: str,
        org_id: str,
        limit: int = 100,
        action: Optional[str] = None,
    ) -> Sequence[AuditLog]:
        query = (
            select(AuditLog)
            .where(AuditLog.agent_id == agent_id, AuditLog.org_id == org_id)
            .order_by(AuditLog.sequence_number.desc())
            .limit(limit)
        )
        if action:
            query = query.where(AuditLog.action == action)
        result = await db.execute(query)
        return result.scalars().all()

    async def get_latest(
        self, db: AsyncSession, org_id: str, limit: int = 50
    ) -> Sequence[AuditLog]:
        result = await db.execute(
            select(AuditLog)
            .where(AuditLog.org_id == org_id)
            .order_by(AuditLog.sequence_number.desc())
            .limit(limit)
        )
        return result.scalars().all()


audit_repo = AuditRepository()
