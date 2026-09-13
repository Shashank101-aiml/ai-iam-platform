"""
Audit Service — query and verification layer over the audit repository.

The repository handles writes; this service handles reads + compliance ops.
"""

import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException

from app.repositories.audit_repo import audit_repo


class AuditService:

    async def get_trace(
        self,
        db: AsyncSession,
        *,
        causal_trace_id: str,
        org_id: str,
    ) -> dict:
        """
        Return the full causal event tree for a trace ID.

        This reconstructs exactly what happened during one agent operation:
        which agent was involved, what credentials were used, what tools
        were called, what was allowed/denied, in chronological order.
        """
        events = await audit_repo.get_by_trace(db, causal_trace_id, org_id)
        if not events:
            raise HTTPException(status_code=404, detail="Trace not found")

        return {
            "causal_trace_id": causal_trace_id,
            "event_count": len(events),
            "events": [self._serialize_event(e) for e in events],
            "timeline": {
                "started_at": events[0].created_at.isoformat(),
                "ended_at": events[-1].created_at.isoformat(),
            },
        }

    async def get_agent_history(
        self,
        db: AsyncSession,
        *,
        agent_id: str,
        org_id: str,
        limit: int = 100,
        action_filter: Optional[str] = None,
    ) -> list[dict]:
        events = await audit_repo.get_by_agent(
            db, agent_id, org_id, limit=limit, action=action_filter
        )
        return [self._serialize_event(e) for e in events]

    async def verify_integrity(
        self,
        db: AsyncSession,
        *,
        org_id: str,
    ) -> dict:
        """
        Run a full chain integrity check for an org's audit log.

        Expensive — run on-demand for compliance audits, not on every request.
        Returns a verification report suitable for compliance documentation.
        """
        is_valid, broken_at, total_checked = await audit_repo.verify_chain(db, org_id)

        report = {
            "org_id": org_id,
            "chain_valid": is_valid,
            "broken_at_sequence": broken_at,
            "total_entries_checked": total_checked,
            "verification_id": str(uuid.uuid4()),
        }

        if not is_valid:
            report["alert"] = (
                f"TAMPER DETECTED: Hash chain broken at sequence {broken_at}. "
                "Audit log may have been modified. Escalate to security team immediately."
            )

        return report

    def _serialize_event(self, event) -> dict:
        return {
            "id": event.id,
            "sequence_number": event.sequence_number,
            "action": event.action,
            "actor_type": event.actor_type,
            "actor_id": event.actor_id,
            "agent_id": event.agent_id,
            "outcome": event.outcome,
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
            "details": event.details,
            "causal_trace_id": event.causal_trace_id,
            "parent_event_id": event.parent_event_id,
            "source_ip": event.source_ip,
            "created_at": event.created_at.isoformat(),
            "entry_hash": event.entry_hash[:16] + "...",  # Truncated — don't expose full hash
        }


audit_service = AuditService()
