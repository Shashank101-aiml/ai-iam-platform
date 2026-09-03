from typing import Optional
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.repositories.base_repo import BaseRepository


class UserRepository(BaseRepository[User]):
    def __init__(self):
        super().__init__(User)

    async def get_by_email(
        self, db: AsyncSession, email: str
    ) -> Optional[User]:
        result = await db.execute(
            select(User).where(User.email == email.lower().strip())
        )
        return result.scalar_one_or_none()

    async def get_by_email_and_org(
        self, db: AsyncSession, email: str, org_id: str
    ) -> Optional[User]:
        result = await db.execute(
            select(User).where(
                and_(User.email == email.lower().strip(), User.org_id == org_id)
            )
        )
        return result.scalar_one_or_none()


user_repo = UserRepository()
