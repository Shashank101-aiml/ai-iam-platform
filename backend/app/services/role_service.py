"""
Role Service — manage roles and assign them to agents.

Roles are additive scope bundles. An agent's effective scopes =
union of all its roles' scopes, intersected with allowed_scopes.

Note: for the deep ReBAC logic, see core/permissions.py (OPA).
Roles here are the coarse-grained grouping layer above OPA.
"""

import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException

from app.models.role import Role
from app.repositories.base_repo import BaseRepository


class RoleRepository(BaseRepository[Role]):
    def __init__(self):
        super().__init__(Role)


role_repo = RoleRepository()


class RoleService:

    async def create_role(
        self,
        db: AsyncSession,
        *,
        org_id: str,
        name: str,
        description: Optional[str],
        scopes: list[str],
    ) -> Role:
        role = Role(
            id=str(uuid.uuid4()),
            org_id=org_id,
            name=name,
            description=description,
            scopes=scopes,
        )
        db.add(role)
        await db.flush()
        await db.refresh(role)
        return role

    async def get_role(
        self, db: AsyncSession, role_id: str, org_id: str
    ) -> Role:
        role = await role_repo.get_by_id(db, role_id)
        if not role or role.org_id != org_id:
            raise HTTPException(status_code=404, detail="Role not found")
        return role

    async def list_roles(
        self, db: AsyncSession, org_id: str
    ) -> list[Role]:
        from sqlalchemy import select
        result = await db.execute(
            select(Role).where(Role.org_id == org_id)
        )
        return result.scalars().all()


role_service = RoleService()
