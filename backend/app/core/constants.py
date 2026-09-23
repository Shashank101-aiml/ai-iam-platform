from enum import Enum


class AgentStatus(str, Enum):
    PENDING = "pending"       # Registered, not yet provisioned
    ACTIVE = "active"         # Provisioned and operational
    SUSPENDED = "suspended"   # Temporarily disabled
    DECOMMISSIONED = "decommissioned"  # Permanently revoked


class CredentialType(str, Enum):
    API_KEY = "api_key"
    JWT = "jwt"
    X509 = "x509"             # SPIFFE/SPIRE issued


class AuditAction(str, Enum):
    # Agent lifecycle
    AGENT_REGISTERED = "agent.registered"
    AGENT_ACTIVATED = "agent.activated"
    AGENT_SUSPENDED = "agent.suspended"
    AGENT_DECOMMISSIONED = "agent.decommissioned"

    # Credentials
    CREDENTIAL_ISSUED = "credential.issued"
    CREDENTIAL_ROTATED = "credential.rotated"
    CREDENTIAL_REVOKED = "credential.revoked"
    CREDENTIAL_USED = "credential.used"

    # Access decisions
    ACCESS_GRANTED = "access.granted"
    ACCESS_DENIED = "access.denied"

    # MCP tool calls
    MCP_TOOL_CALLED = "mcp.tool_called"
    MCP_TOOL_COMPLETED = "mcp.tool_completed"
    MCP_TOOL_BLOCKED = "mcp.tool_blocked"

    # Delegation
    DELEGATION_GRANTED = "delegation.granted"
    DELEGATION_REVOKED = "delegation.revoked"
    DELEGATION_USED = "delegation.used"

    # On-behalf-of human authority grants (Slice 11) — distinct from
    # agent-to-agent delegation above
    ON_BEHALF_OF_GRANTED = "on_behalf_of.granted"
    ON_BEHALF_OF_REVOKED = "on_behalf_of.revoked"

    # Tenant lifecycle
    ORGANIZATION_CREATED = "organization.created"


class PermissionScope(str, Enum):
    """Scopes embedded in agent JWTs — fine-grained, not roles."""
    AGENT_READ = "agent:read"
    AGENT_WRITE = "agent:write"
    TOOL_EXECUTE = "tool:execute"
    AUDIT_READ = "audit:read"
    CREDENTIAL_ROTATE = "credential:rotate"
    DELEGATE = "delegate"


class TokenType(str, Enum):
    ACCESS = "access"
    REFRESH = "refresh"
    DELEGATION = "delegation"
