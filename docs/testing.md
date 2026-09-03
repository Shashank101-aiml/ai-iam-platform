# Running the Test Suite

The test suite runs against a real PostgreSQL database, not SQLite. The
schema uses `JSONB`/`ARRAY` columns and the audit hash-chain's concurrency
guarantee (`app/repositories/audit_repo.py::_get_chain_tip`) is a
`SELECT ... FOR UPDATE` — neither is expressible on SQLite, so testing there
would certify a chain implementation without ever exercising its one
concurrency guarantee.

## 1. Start Postgres

```bash
docker compose -f docker/docker-compose.yml up -d postgres
```

On first start this also provisions a dedicated `aiiam_test_db` database
(`docker/postgres-init/001-create-test-db.sql`, run automatically by the
official Postgres image on init) — separate from `aiiam_db`, the
development database, so the suite can never truncate a developer's own
data.

Already running Postgres some other way? Just make sure a database named
`aiiam_test_db` exists and is reachable, then skip to step 2.

## 2. Point the suite at it (only if you changed defaults)

`tests/conftest.py` defaults `TEST_DATABASE_URL` to:

```text
postgresql+asyncpg://aiiam_user:supersecretpassword@localhost:5432/aiiam_test_db
```

which matches `docker-compose.yml`'s defaults. Override it if your setup
differs:

```bash
export TEST_DATABASE_URL="postgresql+asyncpg://user:pass@host:5432/aiiam_test_db"
```

## 3. Run

```bash
cd backend
pip install -r requirements.txt
pytest -v
```

Each test function creates the full schema at the start of the test and
drops it at the end (`tests/conftest.py::db_session`) — tests are isolated
from each other, but not run in parallel against the same database.

## CI

No CI pipeline exists yet (tracked as its own slice). When one is added, the
straightforward approach is a `postgres:16` GitHub Actions service container
per job, with `TEST_DATABASE_URL` pointed at it directly — that path doesn't
need `docker-compose.yml` or the init script above at all.
