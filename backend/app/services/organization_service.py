import uuid
import re
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException

from app.models.organization import Organization
from app.repositories.organization_repo import org_repo


class OrganizationService:

    async def create(
        self,
        db: AsyncSession,
        *,
        name: str,
        slug: Optional[str] = None,
        actor_id: str,
    ) -> Organization:
        # Auto-generate slug from name if not provided
        derived_slug = slug or self._slugify(name)

        existing = await org_repo.get_by_slug(db, derived_slug)
        if existing:
            raise HTTPException(
                status_code=409,
                detail=f"Organization with slug '{derived_slug}' already exists"
            )

        org = Organization(
            id=str(uuid.uuid4()),
            name=name,
            slug=derived_slug,
            is_active=True,
        )
        return await org_repo.create(db, org)

    async def get_or_404(
        self, db: AsyncSession, org_id: str
    ) -> Organization:
        org = await org_repo.get_by_id(db, org_id)
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        return org

    def _slugify(self, name: str) -> str:
        slug = name.lower().strip()
        slug = re.sub(r"[^\w\s-]", "", slug)
        slug = re.sub(r"[\s_-]+", "-", slug)
        slug = slug.strip("-")
        return slug


org_service = OrganizationService()
