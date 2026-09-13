from datetime import datetime, timezone
from typing import Sequence, Optional
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.on_behalf_of_grant import OnBehalfOfGrant
from app.repositories.base_repo import BaseRepository


class OnBehalfOfGrantRepository(BaseRepository[OnBehalfOfGrant]):
    def __init__(self):
        super().__init__(OnBehalfOfGrant)

    async def get_active_for_agent(
        self, db: AsyncSession, agent_id: str
    ) -> Sequence[OnBehalfOfGrant]:
        """
        Active, unexpired grants for an agent — resolve_on_behalf_of
        picks whichever (if any) covers the requested scope.
        """
        now = datetime.now(timezone.utc)
        result = await db.execute(
            select(OnBehalfOfGrant).where(
                and_(
                    OnBehalfOfGrant.agent_id == agent_id,
                    OnBehalfOfGrant.is_active == True,
                    OnBehalfOfGrant.expires_at > now,
                )
            )
        )
        return result.scalars().all()

    async def get_by_id_and_org(
        self, db: AsyncSession, grant_id: str, org_id: str
    ) -> Optional[OnBehalfOfGrant]:
        result = await db.execute(
            select(OnBehalfOfGrant).where(
                and_(OnBehalfOfGrant.id == grant_id, OnBehalfOfGrant.org_id == org_id)
            )
        )
        return result.scalar_one_or_none()


on_behalf_of_grant_repo = OnBehalfOfGrantRepository()
