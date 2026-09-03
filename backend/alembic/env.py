"""
Alembic Environment script for async SQLAlchemy migrations.
"""

import asyncio
import os
from logging.config import fileConfig
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config
from alembic import context

from app.core.config import settings
from app.models import Base  # Import all models to register metadata

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# Prefer an explicit DATABASE_URL environment variable when set — this is
# the standard Alembic pattern for pointing migrations at a different
# database than the app's own .env (a schema-drift check DB, CI, a
# specific environment) without touching app.core.config. Falls back to
# the app's own configured DATABASE_URL for normal `alembic upgrade head`
# runs against the dev database.
config.set_main_option(
    "sqlalchemy.url", os.environ.get("DATABASE_URL", settings.DATABASE_URL)
)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode without an active DB connection."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations in 'online' mode with an async SQLAlchemy engine."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
