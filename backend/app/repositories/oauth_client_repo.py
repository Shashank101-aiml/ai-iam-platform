from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.oauth_client import OAuthClient
from app.repositories.base_repo import BaseRepository


class OAuthClientRepository(BaseRepository[OAuthClient]):
    def __init__(self):
        super().__init__(OAuthClient)

    async def get_by_client_id(
        self, db: AsyncSession, client_id: str
    ) -> Optional[OAuthClient]:
        result = await db.execute(
            select(OAuthClient).where(OAuthClient.client_id == client_id)
        )
        return result.scalar_one_or_none()


oauth_client_repo = OAuthClientRepository()
