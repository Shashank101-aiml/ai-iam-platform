"""
Database session management and initialization utilities.
Provides clean re-exports of engine, AsyncSessionLocal, get_db, and an init_db
helper for local development and test environment bootstrapping.
"""

from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import engine, AsyncSessionLocal, get_db
from app.models.base import Base


async def init_db() -> None:
    """
    Create database tables asynchronously.
    Used for local development, in-memory SQLite tests, and initial seed scripts.
    In production deployments, Alembic migrations should be run instead.
    """
    async with engine.begin() as conn:
        # Import all models to ensure metadata registry is populated
        import app.models  # noqa: F401
        await conn.run_sync(Base.metadata.create_all)


async def drop_db() -> None:
    """Drop all tables. Used strictly for test teardown."""
    async with engine.begin() as conn:
        import app.models  # noqa: F401
        await conn.run_sync(Base.metadata.drop_all)


__all__ = [
    "engine",
    "AsyncSessionLocal",
    "get_db",
    "init_db",
    "drop_db",
]
