-- Runs once, automatically, on first container init (docker-entrypoint-initdb.d).
-- Provisions databases dedicated to testing so tests never run against —
-- and can never truncate — the development database that shares this
-- same Postgres instance.
CREATE DATABASE aiiam_test_db OWNER aiiam_user;

-- Used only by tests/test_schema_sync.py, which runs real `alembic
-- upgrade head` + `alembic check` against it. Kept separate from
-- aiiam_test_db because that database's schema is built by
-- Base.metadata.create_all/drop_all per test (see tests/conftest.py),
-- not by Alembic — mixing the two would leave an orphaned
-- alembic_version table with no way to know if it's still accurate.
CREATE DATABASE aiiam_schema_check_db OWNER aiiam_user;
