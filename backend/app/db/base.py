"""
Base database module.
Re-exports declarative Base, TimestampMixin, and UUID generator from models.base
so database repositories and Alembic migrations have a clean import path.
"""

from app.models.base import Base, TimestampMixin, generate_uuid

__all__ = ["Base", "TimestampMixin", "generate_uuid"]
