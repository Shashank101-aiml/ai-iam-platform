"""
Organizations API Router.
Manages multi-tenant organization boundaries.

Creating an org and reading across orgs are both superuser-only —
regular operators only ever see their own org. Any org_id in a path
that doesn't belong to the caller (and the caller isn't a superuser)
returns 404, not 403: a 403 confirms the org exists, a 404 doesn't.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.organization import OrganizationCreate, OrganizationResponse
from app.services.organization_service import org_service
from app.repositories.organization_repo import org_repo
from app.api.deps import get_current_user, get_current_superuser
from app.models.user import User

router = APIRouter()


@router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    org_in: OrganizationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_superuser),
):
    """Create a new organization boundary within the AI-IAM platform. Superuser only."""
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
    """Retrieve details of a specific organization. Own org for regular operators; any org for superusers."""
    org = await org_service.get_or_404(db, org_id)
    if org.id != current_user.org_id and not current_user.is_superuser:
        # Same response as "doesn't exist" — a 403 here would confirm to a
        # probing caller that the org_id is valid, just off-limits.
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


@router.get("", response_model=List[OrganizationResponse])
async def list_organizations(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List organizations. Regular operators see only their own; superusers see every tenant."""
    if current_user.is_superuser:
        return await org_repo.list_all(db, skip=skip, limit=limit)
    own_org = await org_repo.get_by_id(db, current_user.org_id)
    return [own_org] if own_org else []
