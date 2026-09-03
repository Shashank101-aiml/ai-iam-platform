"""
Base Repository providing generic async CRUD operations.
All repository classes inherit from BaseRepository[ModelType] to maintain
consistent, typed database interaction patterns across the platform.
"""

from typing import TypeVar, Generic, Optional, Sequence, Type
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession

ModelType = TypeVar("ModelType")


class BaseRepository(Generic[ModelType]):
    def __init__(self, model: Type[ModelType]):
        self.model = model

    async def get_by_id(
        self, db: AsyncSession, id: str
    ) -> Optional[ModelType]:
        """Fetch a single record by its primary key ID."""
        result = await db.execute(
            select(self.model).where(self.model.id == id)
        )
        return result.scalar_one_or_none()

    async def list_all(
        self, db: AsyncSession, skip: int = 0, limit: int = 100
    ) -> Sequence[ModelType]:
        """Fetch a paginated list of records."""
        result = await db.execute(
            select(self.model).offset(skip).limit(limit)
        )
        return result.scalars().all()

    async def create(
        self, db: AsyncSession, obj: ModelType
    ) -> ModelType:
        """Persist a new ORM object to the database."""
        db.add(obj)
        await db.flush()
        await db.refresh(obj)
        return obj

    async def update(
        self, db: AsyncSession, obj: ModelType
    ) -> ModelType:
        """Flush changes made to an existing ORM object."""
        await db.flush()
        await db.refresh(obj)
        return obj

    async def delete(
        self, db: AsyncSession, id: str
    ) -> bool:
        """Delete a record by primary key."""
        result = await db.execute(
            delete(self.model).where(self.model.id == id)
        )
        await db.flush()
        return result.rowcount > 0
