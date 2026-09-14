"""
Users API Router.
Manages operator profiles and permissions.
"""

from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.user import UserResponse
from app.repositories.user_repo import user_repo
from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter()


@router.get("", response_model=List[UserResponse])
async def list_users(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all human operators across the organization."""
    from sqlalchemy import select
    result = await db.execute(
        select(User).where(User.org_id == current_user.org_id).offset(skip).limit(limit)
    )
    return result.scalars().all()


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve specific user details."""
    from fastapi import HTTPException
    user = await user_repo.get_by_id(db, user_id)
    if not user or user.org_id != current_user.org_id:
        raise HTTPException(status_code=404, detail="User not found")
    return user
