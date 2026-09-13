"""
OAuth 2.1 / MCP resource-server compliance schemas.

Covers RFC 7591 (Dynamic Client Registration), RFC 8414 (Authorization
Server Metadata), RFC 9728 (Protected Resource Metadata), and the
authorization_code + PKCE token response (RFC 6749 §5.1, as narrowed
by OAuth 2.1). See api/oauth.py for the routes that use these.
"""

from typing import Optional, List, Literal
from pydantic import BaseModel, Field


# ── RFC 7591: Dynamic Client Registration ────────────────────────────────────

class ClientRegistrationRequest(BaseModel):
    client_name: str = Field(..., min_length=1, max_length=255)
    redirect_uris: List[str] = Field(..., min_length=1)
    # "web" (https-only redirects) or "native" (desktop/CLI — loopback
    # http://127.0.0.1:<port>/... and http://localhost:<port>/...
    # redirects allowed per RFC 8252). Determines which redirect_uris
    # oauth_service.py's validation accepts.
    application_type: Literal["web", "native"] = "web"
    grant_types: Optional[List[str]] = None
    response_types: Optional[List[str]] = None
    # Accepted for RFC 7591 wire-compatibility but never honored as
    # anything other than "none" — see models/oauth_client.py's
    # docstring for why every client here is a PKCE-only public client.
    token_endpoint_auth_method: Optional[str] = None


class ClientRegistrationResponse(BaseModel):
    client_id: str
    client_id_issued_at: int
    client_name: str
    redirect_uris: List[str]
    application_type: str
    grant_types: List[str]
    response_types: List[str]
    token_endpoint_auth_method: str = "none"


# ── RFC 8414: Authorization Server Metadata ──────────────────────────────────

class AuthorizationServerMetadata(BaseModel):
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    registration_endpoint: str
    jwks_uri: str
    scopes_supported: List[str]
    response_types_supported: List[str] = ["code"]
    grant_types_supported: List[str] = ["authorization_code"]
    token_endpoint_auth_methods_supported: List[str] = ["none"]
    code_challenge_methods_supported: List[str] = ["S256"]
    # Not a registered RFC 8414 field — an informal extension MCP-
    # ecosystem clients/servers look for to confirm RFC 8707 support
    # before sending a resource= parameter.
    resource_indicators_supported: bool = True


# ── RFC 9728: OAuth 2.0 Protected Resource Metadata ───────────────────────────

class ProtectedResourceMetadata(BaseModel):
    resource: str
    authorization_servers: List[str]
    bearer_methods_supported: List[str] = ["header"]
    scopes_supported: List[str]


# ── Authorization Code + PKCE flow ────────────────────────────────────────────

class OAuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    scope: str  # space-separated, per RFC 6749 — not a list, unlike AgentJwtResponse
