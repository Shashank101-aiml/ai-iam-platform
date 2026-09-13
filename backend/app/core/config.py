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
    SPIFFE_TRUST_DOMAIN: str = "ai-iam.example.com"
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

    # MCP proxy — bounding the blast radius of a slow, wedged, or
    # malicious/compromised downstream MCP server. mcp_server_url is never
    # taken from the caller (see mcp_proxy_service._resolve_mcp_binding) —
    # these settings bound what happens once the proxy calls a URL it
    # resolved itself.
    MCP_CALL_TIMEOUT_SECONDS: float = 30.0
    MCP_MAX_RESPONSE_BYTES: int = 1_048_576  # 1 MiB — results are hashed, never rendered; no legitimate tool needs more
    MCP_CIRCUIT_BREAKER_FAILURE_THRESHOLD: int = 5  # consecutive failures before a server is short-circuited
    MCP_CIRCUIT_BREAKER_COOLDOWN_SECONDS: float = 30.0

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
