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

    # OAuth 2.1 / MCP resource-server compliance (RFC 8414 discovery,
    # RFC 9728 protected-resource metadata, RFC 7591 Dynamic Client
    # Registration, RFC 8707 Resource Indicators) — see api/oauth.py.
    # This platform IS the Authorization Server (it already mints its
    # own RS256 tokens) and the MCP proxy IS the protected resource;
    # PUBLIC_BASE_URL is the externally-reachable origin both discovery
    # documents advertise their endpoints under. Must be set to the
    # real public origin outside local dev — discovery documents built
    # from "http://localhost:8000" are useless to any client that isn't
    # also running on the same machine.
    PUBLIC_BASE_URL: str = "http://localhost:8000"
    # How long an issued authorization `code` stays redeemable —
    # OAuth 2.1 recommends short-lived, single-use codes; this is
    # generous enough for a real redirect round-trip, not for leaving a
    # code sitting in a browser history.
    OAUTH_AUTHORIZATION_CODE_TTL_SECONDS: int = 120

    # CORS. Never combine a wildcard origin with allow_credentials=True
    # (main.py) — that combination is invalid per the Fetch/CORS spec,
    # and every real browser refuses to honor the resulting
    # Access-Control-Allow-Origin: * header when credentials are also
    # requested, so allow_origins=["*"] + allow_credentials=True was
    # never actually working for a credentialed cross-origin request in
    # the first place — it just failed silently in the browser instead
    # of the server. This must always be a real, explicit origin list.
    CORS_ALLOWED_ORIGINS: list[str] = ["http://localhost:5173"]

    # Rate limiting (Slice 15) — /auth/login and /token/exchange both do
    # bcrypt work (BCRYPT_ROUNDS=12, deliberately slow) on completely
    # unauthenticated input; without a limit either is a cheap CPU-
    # exhaustion vector. Enforced in core/rate_limit.py against Redis
    # (already a hard dependency) rather than in-process memory — an
    # in-process counter would only bound each of the 4 uvicorn worker
    # processes independently, letting a client get up to 4x the
    # intended limit depending on which worker happened to handle each
    # request.
    RATE_LIMIT_LOGIN_PER_MINUTE: int = 10
    RATE_LIMIT_TOKEN_EXCHANGE_PER_MINUTE: int = 60
    # Tighter than login: this does a DB write (new org + new user) plus
    # a bcrypt hash on completely unauthenticated input, not just a read.
    RATE_LIMIT_TRIAL_SIGNUP_PER_MINUTE: int = 3

    # Task-scoped tokens (Slice 12) — Stacklok's "ambient authority"
    # problem: a bearer token today authorizes ANY tool call its scopes
    # allow for its whole 15-minute lifetime, not just the one call it
    # was minted for. An RFC 9396-style authorization_details claim
    # (core/jwt.py) can bind a token to ONE specific (mcp_server_id,
    # tool_name) pair at mint time; mcp_proxy_service then refuses any
    # OTHER call even if scopes/OPA would allow it. Opt-in everywhere
    # except these scopes, where the stronger model is mandatory — a
    # token requesting one of these without task-scoping is refused at
    # mint time, not silently issued session-scoped.
    MCP_TASK_SCOPING_REQUIRED_SCOPES: list[str] = ["credential:rotate"]

    # SSRF allowlist for mcp_bindings[].server_url, enforced at agent
    # registration (agent_service.register). The proxy already refuses to
    # take a URL from a tool-call request body, but the binding's own
    # server_url used to be trusted on the grounds that it is
    # "operator-authored" — an assumption that stopped holding once
    # POST /auth/trial-signup let anyone become an operator of their own
    # org: without this check, a visitor could register an agent bound to
    # http://postgres:5432 or http://opa:8181 and have the proxy POST
    # /tools/<name> to it from inside the network. Fail-closed default:
    # only the bundled mock MCP server's hostnames. A real deployment
    # must set this (env var, JSON list) to the hostnames of the MCP
    # servers it actually uses.
    MCP_SERVER_URL_ALLOWED_HOSTS: list[str] = ["mock-mcp", "security-mcp", "data-mcp"]

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
