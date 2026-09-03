"""
API Keys Router.
Enforces zero-downtime credential rotation with configurable grace windows
and returns plaintext secrets exactly once.

Issuing and listing keys for an agent live on the agents router
(POST/GET /api/v1/agents/{agent_id}/keys) — those routes are scoped to a
specific agent, whereas rotate/revoke here operate on an existing key by
its own key_id. Keeping "identified by agent_id" and "identified by
key_id" operations on visibly different URL shapes avoids a path like
`/keys/{agent_id}` sitting next to `/keys/{key_id}` where the two path
parameters mean completely different things.
"""

from fastapi import APIRouter, Depends, status, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.services.api_key_service import api_key_service
from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter()


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
