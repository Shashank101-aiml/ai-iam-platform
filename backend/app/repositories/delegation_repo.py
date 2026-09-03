"""
Delegation Grant Repository.
Handles queries for active multi-hop delegation grants and JTI lookups.
"""

from typing import Optional, Sequence
from datetime import datetime, timezone
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.delegation_grant import DelegationGrant
from app.repositories.base_repo import BaseRepository


class DelegationRepository(BaseRepository[DelegationGrant]):
    def __init__(self):
        super().__init__(DelegationGrant)

    async def get_by_jti(
        self, db: AsyncSession, jti: str
    ) -> Optional[DelegationGrant]:
        """Fetch a delegation grant by its unique JWT ID (`jti`)."""
        result = await db.execute(
            select(DelegationGrant).where(DelegationGrant.delegation_jti == jti)
        )
        return result.scalar_one_or_none()

    async def get_active_for_delegatee(
        self, db: AsyncSession, delegatee_agent_id: str, org_id: str
    ) -> Sequence[DelegationGrant]:
        """Fetch all active, unexpired delegation grants where agent is the delegatee."""
        now = datetime.now(timezone.utc)
        result = await db.execute(
            select(DelegationGrant).where(
                and_(
                    DelegationGrant.delegatee_agent_id == delegatee_agent_id,
                    DelegationGrant.org_id == org_id,
                    DelegationGrant.is_active == True,
                    DelegationGrant.expires_at > now,
                )
            ).order_by(DelegationGrant.created_at.desc())
        )
        return result.scalars().all()

    async def get_active_for_delegator(
        self, db: AsyncSession, delegating_agent_id: str, org_id: str
    ) -> Sequence[DelegationGrant]:
        """Fetch all active delegation grants issued by this agent."""
        now = datetime.now(timezone.utc)
        result = await db.execute(
            select(DelegationGrant).where(
                and_(
                    DelegationGrant.delegating_agent_id == delegating_agent_id,
                    DelegationGrant.org_id == org_id,
                    DelegationGrant.is_active == True,
                    DelegationGrant.expires_at > now,
                )
            ).order_by(DelegationGrant.created_at.desc())
        )
        return result.scalars().all()

    async def list_by_org(
        self, db: AsyncSession, org_id: str, skip: int = 0, limit: int = 100
    ) -> Sequence[DelegationGrant]:
        result = await db.execute(
            select(DelegationGrant)
            .where(DelegationGrant.org_id == org_id)
            .order_by(DelegationGrant.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()


delegation_repo = DelegationRepository()
