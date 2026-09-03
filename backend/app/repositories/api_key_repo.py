from typing import Optional, Sequence
from datetime import datetime, timezone

from sqlalchemy import select, update, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_key import ApiKey
from app.repositories.base_repo import BaseRepository


class ApiKeyRepository(BaseRepository[ApiKey]):
    def __init__(self):
        super().__init__(ApiKey)

    async def get_by_key_id(
        self, db: AsyncSession, key_id: str
    ) -> Optional[ApiKey]:
        """
        Look up by key_id (the safe-to-log identifier).
        Used in audit log lookups — never for auth verification.
        """
        result = await db.execute(
            select(ApiKey).where(ApiKey.key_id == key_id)
        )
        return result.scalar_one_or_none()

    async def get_active_keys_for_agent(
        self, db: AsyncSession, agent_id: str
    ) -> Sequence[ApiKey]:
        result = await db.execute(
            select(ApiKey).where(
                and_(
                    ApiKey.agent_id == agent_id,
                    ApiKey.is_active == True,
                )
            )
        )
        return result.scalars().all()

    async def get_all_keys_for_agent(
        self, db: AsyncSession, agent_id: str
    ) -> Sequence[ApiKey]:
        result = await db.execute(
            select(ApiKey)
            .where(ApiKey.agent_id == agent_id)
            .order_by(ApiKey.created_at.desc())
        )
        return result.scalars().all()

    async def deactivate_key(
        self, db: AsyncSession, key_id: str
    ) -> bool:
        result = await db.execute(
            update(ApiKey)
            .where(ApiKey.key_id == key_id)
            .values(is_active=False, updated_at=datetime.now(timezone.utc))
            .returning(ApiKey.id)
        )
        await db.flush()
        return result.scalar_one_or_none() is not None

    async def record_usage(
        self, db: AsyncSession, key_id: str
    ) -> None:
        """
        Update last_used_at and increment use_count.
        Called on every successful API key authentication.
        """
        await db.execute(
            update(ApiKey)
            .where(ApiKey.key_id == key_id)
            .values(
                last_used_at=datetime.now(timezone.utc),
                use_count=ApiKey.use_count + 1,
            )
        )
        await db.flush()

    async def store_rotation(
        self,
        db: AsyncSession,
        old_key_id: str,
        new_key: ApiKey,
        grace_period_hash: str,
        grace_expires_at: datetime,
    ) -> ApiKey:
        """
        Zero-downtime rotation:
        1. Persist the new key as active
        2. Store the old hash in previous_hashed_secret for grace period
        3. Deactivate the old key but keep it readable for audit
        """
        # Attach old key's hash to new key for grace period acceptance
        new_key.previous_hashed_secret = grace_period_hash
        new_key.previous_key_expires_at = grace_expires_at

        db.add(new_key)
        await db.flush()

        # Deactivate old key
        await db.execute(
            update(ApiKey)
            .where(ApiKey.key_id == old_key_id)
            .values(
                is_active=False,
                rotated_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
        )
        await db.flush()
        await db.refresh(new_key)
        return new_key

    async def get_keys_needing_rotation(
        self, db: AsyncSession
    ) -> Sequence[ApiKey]:
        """Used by worker/credential_rotator.py to find keys near expiry."""
        from app.core.security import should_rotate_key
        from app.core.config import settings

        # Fetch all active non-expiring keys; filtering happens in Python
        # because "last 20% of TTL" isn't a simple SQL expression here
        result = await db.execute(
            select(ApiKey).where(
                and_(
                    ApiKey.is_active == True,
                    ApiKey.expires_at.isnot(None),
                )
            )
        )
        keys = result.scalars().all()
        return [
            k for k in keys
            if should_rotate_key(k.created_at, settings.API_KEY_DEFAULT_TTL_DAYS)
        ]


api_key_repo = ApiKeyRepository()
