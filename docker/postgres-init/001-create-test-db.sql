-- Runs once, automatically, on first container init (docker-entrypoint-initdb.d).
-- Provisions a second database dedicated to the test suite so tests never
-- run against — and can never truncate — the development database that
-- shares this same Postgres instance.
CREATE DATABASE aiiam_test_db OWNER aiiam_user;
