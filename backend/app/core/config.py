from pydantic_settings import BaseSettings
from typing import Optional
from functools import lru_cache


class Settings(BaseSettings):
    # App
    APP_NAME: str = "AI-IAM Platform"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"

    # PostgreSQL
    DATABASE_URL: str
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20

    # JWT — keep these short for agents (not humans)
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "RS256"           # Asymmetric — public key can be shared for verification
    JWT_PRIVATE_KEY_PATH: str = "keys/private.pem"
    JWT_PUBLIC_KEY_PATH: str = "keys/public.pem"

    # Agent credential TTLs — deliberately short
    AGENT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15   # 15 min max for agent tokens
    AGENT_REFRESH_TOKEN_EXPIRE_HOURS: int = 2     # 2 hr refresh window
    API_KEY_DEFAULT_TTL_DAYS: int = 30

    # SPIFFE — workload identity
    SPIFFE_TRUST_DOMAIN: str = "ai-iam.internal"
    SPIRE_AGENT_SOCKET: Optional[str] = "/tmp/spire-agent/public/api.sock"

    # OPA — policy engine
    OPA_URL: str = "http://localhost:8181"
    OPA_POLICY_PATH: str = "v1/data/aiiam/authz"
    # Refuse to start if OPA is unreachable (see core/permissions.py's
    # verify_opa_reachable, called from main.py's lifespan). A policy
    # engine that's silently unreachable would deny every real request
    # forever while looking "up" from the outside — better to never
    # accept traffic. Set False only for narrow local work that
    # genuinely doesn't exercise policy enforcement.
    OPA_REQUIRED: bool = True

    # Security hardening
    BCRYPT_ROUNDS: int = 12
    MAX_DELEGATION_DEPTH: int = 5          # Prevent infinite agent → agent chains
    API_KEY_PREFIX: str = "aiiam_"         # Prefix lets you grep logs/github safely

    # Audit
    AUDIT_HASH_ALGORITHM: str = "sha256"   # For append-only chain integrity
    # The audit writer connects to Postgres as its OWN least-privileged
    # role (INSERT + SELECT on audit_logs only — see migration
    # 0003_audit_log_durability), never as the app's own DATABASE_URL
    # role, which has full CRUD on every other table. app/db/session.py
    # derives the audit connection string from DATABASE_URL with just
    # these credentials swapped in, unless AUDIT_DATABASE_URL is set
    # explicitly (tests point this at the test database instead).
    AUDIT_DB_USER: str = "aiiam_audit_writer"
    AUDIT_DB_PASSWORD: str = "audit_writer_dev_password"
    AUDIT_DATABASE_URL: Optional[str] = None
    # This Postgres instance has no TLS certificates configured at all —
    # asyncpg/SQLAlchemy's default "prefer" SSL negotiation still attempts
    # opportunistic TLS regardless, and for a manually CREATE ROLE'd
    # account (SCRAM auth, unlike the POSTGRES_USER-bootstrapped app role)
    # that negotiation reliably surfaces as a misleading
    # InvalidPasswordError instead of a TLS error — confirmed by the same
    # credentials connecting fine with SSL off. Set False only once this
    # database actually has TLS set up.
    AUDIT_DB_SSL: bool = False
    AUDIT_VERIFY_BATCH_SIZE: int = 1000  # verify_chain streams in batches this size, never loads a whole org's chain into memory
    # The verifier worker re-hashes an org's ENTIRE chain from genesis on
    # every run — cheap in memory (streamed), not in time for a
    # long-lived org, so this runs far less often than the credential
    # rotation loop, not on the same cadence.
    AUDIT_VERIFY_INTERVAL_SECONDS: int = 3600

    # MCP proxy — bounding the blast radius of a slow, wedged, or
    # malicious/compromised downstream MCP server. mcp_server_url is never
    # taken from the caller (see mcp_proxy_service._resolve_mcp_binding) —
    # these settings bound what happens once the proxy calls a URL it
    # resolved itself.
    MCP_CALL_TIMEOUT_SECONDS: float = 30.0
    MCP_MAX_RESPONSE_BYTES: int = 1_048_576  # 1 MiB — results are hashed, never rendered; no legitimate tool needs more
    MCP_CIRCUIT_BREAKER_FAILURE_THRESHOLD: int = 5  # consecutive failures before a server is short-circuited
    MCP_CIRCUIT_BREAKER_COOLDOWN_SECONDS: float = 30.0

    # Revocation index — see app/core/revocation.py. Short token TTLs
    # (15 min for agent access tokens) limit exposure but are not
    # revocation: a suspended agent's or revoked delegation's tokens
    # would otherwise keep working until they naturally expire. Fail
    # closed on Redis being unreachable, the same choice already made
    # for OPA (verify_opa_reachable) and for the same reason — a
    # revocation index that's silently unreachable would let every
    # already-revoked token through while looking "up" from the
    # outside; refusing to boot / refusing the request is the honest
    # failure mode, not silently trusting a token we can't check.
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_REQUIRED: bool = True

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
