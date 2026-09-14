from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool
from app.core.config import settings

# Convert standard postgres:// to postgresql+asyncpg://
DATABASE_URL = settings.DATABASE_URL.replace(
    "postgresql://", "postgresql+asyncpg://"
).replace("postgres://", "postgresql+asyncpg://")

engine = create_async_engine(
    DATABASE_URL,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    # NOT settings.DEBUG — SQLAlchemy's echo=True is a logging SHORTCUT
    # that self-installs its own plain-text StreamHandler directly onto
    # the "sqlalchemy.engine.Engine" logger the moment it finds that
    # SPECIFIC logger has no handlers of its own — a check against that
    # child logger's own (always-empty-by-default) handler list, not
    # root's, so nothing about when/whether core.logging_config's
    # configure_logging() has already run prevents it. Confirmed live
    # (Slice 14): every SQL log line was emitted TWICE — once via
    # SQLAlchemy's own plain-text handler, once via propagation to
    # root's structured JSON one. echo=False here; configure_logging()
    # instead sets this same logger's LEVEL directly, so SQL statements
    # still show up in DEBUG mode, but through the app's one JSON
    # handler via ordinary propagation, not a second competing one.
    echo=False,
    future=True,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncSession:
    """FastAPI dependency — yields a DB session per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


def _build_audit_database_url() -> str:
    """
    The audit writer connects to the same physical database as the app,
    but as its own least-privileged Postgres role (see migration
    0003_audit_log_durability) — never as the app's own DATABASE_URL
    role, which has full CRUD everywhere else. Reusing DATABASE_URL's
    host/port/database and swapping only the credentials keeps this in
    sync with wherever the app's database actually lives in any given
    environment. AUDIT_DATABASE_URL, when set, overrides this entirely —
    tests use it to point the audit writer at the test database instead.
    """
    if settings.AUDIT_DATABASE_URL:
        return settings.AUDIT_DATABASE_URL.replace(
            "postgresql://", "postgresql+asyncpg://"
        ).replace("postgres://", "postgresql+asyncpg://")
    # render_as_string(hide_password=False) — NOT bare str(url)/repr(url),
    # which SQLAlchemy masks to a literal "***" by default for safe
    # logging. Using str() here would silently build a connection string
    # containing the three characters "***" as the password instead of
    # the real one — every connection attempt would then fail
    # authentication with no obvious clue why.
    return make_url(DATABASE_URL).set(
        username=settings.AUDIT_DB_USER,
        password=settings.AUDIT_DB_PASSWORD,
    ).render_as_string(hide_password=False)


AUDIT_DATABASE_URL = _build_audit_database_url()

# NullPool, not a real pool: audit_repo.append() opens one of these,
# uses it for one short-lived commit, and closes it — infrequent enough
# that a fresh connection per call costs nothing worth optimizing for,
# and it sidesteps the exact class of pooled-connection-left-in-a-weird-
# state bug this project already hit once with the test suite's own
# engine (see conftest.py's test_engine — same rationale, same fix).
audit_engine = create_async_engine(
    AUDIT_DATABASE_URL,
    poolclass=NullPool,
    # NOT settings.DEBUG — see the `engine` definition above for why.
    echo=False,
    future=True,
    connect_args={} if settings.AUDIT_DB_SSL else {"ssl": False},
)

# Deliberately its own sessionmaker, never shared with AsyncSessionLocal —
# see app/repositories/audit_repo.py for why audit writes never take the
# caller's db session at all.
AuditSessionLocal = async_sessionmaker(
    audit_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)
