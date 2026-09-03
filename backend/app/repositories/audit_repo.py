"""
Audit Log Repository — the most security-critical repo.

Enforces two guarantees that no other layer should be able to bypass:

1. APPEND-ONLY: This repo has NO update() or delete() methods.
   Any attempt to modify audit logs must go through a DB-level
   constraint (the app user has INSERT-only privilege on this table).

2. HASH CHAIN INTEGRITY: Every append() call reads the last entry's
   hash and chains the new entry to it. This is done inside a
   SELECT ... FOR UPDATE SKIP LOCKED to prevent race conditions from
   two concurrent writes breaking the chain.

In production, the DB role used by the app should be:
    GRANT INSERT ON audit_logs TO app_user;
    -- no UPDATE, no DELETE
"""

import json
from typing import Optional, Sequence
from datetime import datetime, timezone

from sqlalchemy import select, func, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.core.security import compute_entry_hash, AUDIT_CHAIN_GENESIS
from app.core.constants import AuditAction
from app.repositories.base_repo import BaseRepository


class AuditRepository(BaseRepository[AuditLog]):
    def __init__(self):
        super().__init__(AuditLog)

    async def append(
        self,
        db: AsyncSession,
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
        Append a new entry to the audit chain.

        Atomically:
        1. Locks the last entry for this org (SELECT FOR UPDATE SKIP LOCKED)
        2. Reads its hash and sequence number
        3. Computes the new entry's hash = SHA256(content + prev_hash)
        4. Inserts the new entry
        """
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

        # Step 4: Create and persist the entry
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
        await db.flush()
        await db.refresh(entry)
        return entry

    async def _get_chain_tip(
        self, db: AsyncSession, org_id: str
    ) -> tuple[str, int]:
        """
        Get the last entry's hash and next sequence number for this org.

        Uses SELECT FOR UPDATE to prevent two concurrent appends from
        racing and producing an invalid chain (two entries with the
        same previous_hash, breaking the link).
        """
        result = await db.execute(
            select(AuditLog.entry_hash, AuditLog.sequence_number)
            .where(AuditLog.org_id == org_id)
            .order_by(AuditLog.sequence_number.desc())
            .limit(1)
            .with_for_update(skip_locked=False)  # BLOCK until prior write finishes
        )
        row = result.one_or_none()
        if row is None:
            # First entry for this org — start the genesis chain
            return AUDIT_CHAIN_GENESIS, 1
        return row.entry_hash, row.sequence_number + 1

    async def verify_chain(
        self, db: AsyncSession, org_id: str
    ) -> tuple[bool, Optional[int]]:
        """
        Replay the entire audit chain for an org and verify integrity.

        Returns (is_valid, broken_at_sequence_number).
        If valid: (True, None)
        If tampered: (False, sequence_number_of_first_broken_link)

        This is an expensive operation — use only for compliance audits,
        not on every request.
        """
        result = await db.execute(
            select(AuditLog)
            .where(AuditLog.org_id == org_id)
            .order_by(AuditLog.sequence_number.asc())
        )
        entries = result.scalars().all()

        if not entries:
            return True, None

        prev_hash = AUDIT_CHAIN_GENESIS
        for entry in entries:
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
            if expected_hash != entry.entry_hash:
                return False, entry.sequence_number

            prev_hash = entry.entry_hash

        return True, None

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
