"""
Organizations API Router.
Manages multi-tenant organization boundaries.
"""

from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.organization import OrganizationCreate, OrganizationResponse
from app.services.organization_service import org_service
from app.repositories.organization_repo import org_repo
from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter()


@router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    org_in: OrganizationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new organization boundary within the AI-IAM platform."""
    org = await org_service.create(
        db,
        name=org_in.name,
        slug=org_in.slug,
        actor_id=current_user.id,
    )
    await db.commit()
    await db.refresh(org)
    return org


@router.get("/{org_id}", response_model=OrganizationResponse)
async def get_organization(
    org_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve details of a specific organization by ID."""
    return await org_service.get_or_404(db, org_id)


@router.get("", response_model=List[OrganizationResponse])
async def list_organizations(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List organizations visible to the current operator."""
    return await org_repo.list_all(db, skip=skip, limit=limit)
