"""
Role Repository.
Provides queries for role lookups, org-scoped listing, and agent-role assignments.
"""

from typing import Optional, Sequence
from sqlalchemy import select, and_, insert, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.role import Role, agent_roles
from app.repositories.base_repo import BaseRepository


class RoleRepository(BaseRepository[Role]):
    def __init__(self):
        super().__init__(Role)

    async def get_by_name_and_org(
        self, db: AsyncSession, name: str, org_id: str
    ) -> Optional[Role]:
        result = await db.execute(
            select(Role).where(
                and_(Role.name == name, Role.org_id == org_id)
            )
        )
        return result.scalar_one_or_none()

    async def list_by_org(
        self, db: AsyncSession, org_id: str
    ) -> Sequence[Role]:
        result = await db.execute(
            select(Role).where(Role.org_id == org_id).order_by(Role.name.asc())
        )
        return result.scalars().all()

    async def assign_to_agent(
        self, db: AsyncSession, agent_id: str, role_id: str
    ) -> None:
        """Assign a role to an agent if not already assigned."""
        check = await db.execute(
            select(agent_roles).where(
                and_(
                    agent_roles.c.agent_id == agent_id,
                    agent_roles.c.role_id == role_id,
                )
            )
        )
        if not check.first():
            await db.execute(
                insert(agent_roles).values(agent_id=agent_id, role_id=role_id)
            )
            await db.flush()

    async def unassign_from_agent(
        self, db: AsyncSession, agent_id: str, role_id: str
    ) -> None:
        await db.execute(
            delete(agent_roles).where(
                and_(
                    agent_roles.c.agent_id == agent_id,
                    agent_roles.c.role_id == role_id,
                )
            )
        )
        await db.flush()

    async def get_roles_for_agent(
        self, db: AsyncSession, agent_id: str
    ) -> Sequence[Role]:
        result = await db.execute(
            select(Role)
            .join(agent_roles, Role.id == agent_roles.c.role_id)
            .where(agent_roles.c.agent_id == agent_id)
        )
        return result.scalars().all()


role_repo = RoleRepository()
