"""
Audit Logs API Router.
Provides endpoints for querying the append-only SHA256 hash chain, reconstructing
full causal trace trees (`get_trace`), and running cryptographic verification (`verify_integrity`).
"""

from typing import List, Optional
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.audit_log import (
    AuditLogResponse,
    IntegrityVerificationReport,
)
from app.services.audit_service import audit_service
from app.repositories.audit_repo import audit_repo
from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter()


@router.get("/logs", response_model=List[AuditLogResponse])
async def list_audit_logs(
    agent_id: Optional[str] = None,
    action: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Query paginated append-only audit events scoped to the operator's organization."""
    if agent_id:
        events = await audit_repo.get_by_agent(
            db, agent_id=agent_id, org_id=current_user.org_id, limit=limit, action=action
        )
        return events
    else:
        events = await audit_repo.get_latest(db, org_id=current_user.org_id, limit=limit)
        if action:
            events = [e for e in events if e.action == action]
        return events


@router.get("/trace/{causal_trace_id}")
async def get_causal_trace(
    causal_trace_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Reconstruct the exact causal tree and timeline for a specific agent operation."""
    return await audit_service.get_trace(
        db, causal_trace_id=causal_trace_id, org_id=current_user.org_id
    )


@router.get("/verify", response_model=IntegrityVerificationReport)
async def verify_audit_chain(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Trigger full verification of the SHA256 sequence hash chain (`content + previous_hash`).
    Returns compliance status and alerts immediately if any row tampering is detected.
    """
    report = await audit_service.verify_integrity(db, org_id=current_user.org_id)
    from datetime import datetime, timezone
    return {
        "org_id": report["org_id"],
        "chain_valid": report["chain_valid"],
        "broken_at_sequence": report.get("broken_at_sequence"),
        "total_entries_checked": report["total_entries_checked"],
        "verified_at": datetime.now(timezone.utc),
    }
