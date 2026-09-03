"""
API Keys Router.
Enforces zero-downtime credential rotation with configurable grace windows
and returns plaintext secrets exactly once.
"""

from typing import List
from fastapi import APIRouter, Depends, status, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.api_key import (
    ApiKeyIssueRequest,
    ApiKeyIssueResponse,
    ApiKeySummaryResponse,
)
from app.services.api_key_service import api_key_service
from app.repositories.api_key_repo import api_key_repo
from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter()


@router.post("/{agent_id}", response_model=ApiKeyIssueResponse, status_code=status.HTTP_201_CREATED)
async def issue_api_key(
    agent_id: str,
    key_in: ApiKeyIssueRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Issue a new API key (`aiiam_...`) for an active agent."""
    result = await api_key_service.issue_key(
        db,
        agent_id=agent_id,
        org_id=current_user.org_id,
        scopes=key_in.scopes,
        ttl_days=key_in.ttl_days,
        actor_id=f"user:{current_user.id}",
        source_ip=request.client.host if request.client else None,
    )
    await db.commit()
    return result


@router.post("/{key_id}/rotate", status_code=status.HTTP_200_OK)
async def rotate_api_key(
    key_id: str,
    request: Request,
    grace_period_hours: int = 2,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Proactively rotate a key with a configurable grace window (`previous_hashed_secret`)."""
    result = await api_key_service.rotate_key(
        db,
        key_id=key_id,
        org_id=current_user.org_id,
        actor_id=f"user:{current_user.id}",
        grace_period_hours=grace_period_hours,
        source_ip=request.client.host if request.client else None,
    )
    await db.commit()
    return result


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    key_id: str,
    request: Request,
    reason: str = "Revoked via API",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Immediately revoke an API key."""
    await api_key_service.revoke_key(
        db,
        key_id=key_id,
        org_id=current_user.org_id,
        reason=reason,
        actor_id=f"user:{current_user.id}",
        source_ip=request.client.host if request.client else None,
    )
    await db.commit()


@router.get("/agent/{agent_id}", response_model=List[ApiKeySummaryResponse])
async def list_agent_keys(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all API keys belonging to a specific agent."""
    return await api_key_repo.get_all_keys_for_agent(db, agent_id)
