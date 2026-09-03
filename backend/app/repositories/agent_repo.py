from typing import Optional, Sequence
from datetime import datetime, timezone

from sqlalchemy import select, update, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.core.constants import AgentStatus
from app.repositories.base_repo import BaseRepository


class AgentRepository(BaseRepository[Agent]):
    def __init__(self):
        super().__init__(Agent)

    async def get_by_id_and_org(
        self, db: AsyncSession, agent_id: str, org_id: str
    ) -> Optional[Agent]:
        """Org-scoped lookup — always use this in API handlers to prevent
        cross-tenant data access."""
        result = await db.execute(
            select(Agent).where(
                and_(Agent.id == agent_id, Agent.org_id == org_id)
            )
        )
        return result.scalar_one_or_none()

    async def get_by_spiffe_id(
        self, db: AsyncSession, spiffe_id: str
    ) -> Optional[Agent]:
        result = await db.execute(
            select(Agent).where(Agent.spiffe_id == spiffe_id)
        )
        return result.scalar_one_or_none()

    async def list_by_org(
        self,
        db: AsyncSession,
        org_id: str,
        status: Optional[AgentStatus] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Sequence[Agent]:
        query = select(Agent).where(Agent.org_id == org_id)
        if status:
            query = query.where(Agent.status == status)
        query = query.offset(skip).limit(limit)
        result = await db.execute(query)
        return result.scalars().all()

    async def list_by_parent(
        self, db: AsyncSession, parent_agent_id: str
    ) -> Sequence[Agent]:
        """Return all child agents of a given orchestrator agent."""
        result = await db.execute(
            select(Agent).where(Agent.parent_agent_id == parent_agent_id)
        )
        return result.scalars().all()

    async def update_status(
        self, db: AsyncSession, agent_id: str, status: AgentStatus
    ) -> bool:
        result = await db.execute(
            update(Agent)
            .where(Agent.id == agent_id)
            .values(status=status, updated_at=datetime.now(timezone.utc))
            .returning(Agent.id)
        )
        await db.flush()
        return result.scalar_one_or_none() is not None

    async def set_spiffe_id(
        self, db: AsyncSession, agent_id: str, spiffe_id: str
    ) -> bool:
        result = await db.execute(
            update(Agent)
            .where(Agent.id == agent_id)
            .values(spiffe_id=spiffe_id, updated_at=datetime.now(timezone.utc))
            .returning(Agent.id)
        )
        await db.flush()
        return result.scalar_one_or_none() is not None

    async def get_expiring_ephemeral(
        self, db: AsyncSession, before: datetime
    ) -> Sequence[Agent]:
        """Used by the worker to find ephemeral agents that need decommissioning."""
        result = await db.execute(
            select(Agent).where(
                and_(
                    Agent.is_ephemeral == True,
                    Agent.decommission_at <= before,
                    Agent.status == AgentStatus.ACTIVE,
                )
            )
        )
        return result.scalars().all()


agent_repo = AgentRepository()
