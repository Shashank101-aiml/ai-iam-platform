"""
OAuth/MCP discovery documents — RFC 8414 (Authorization Server
Metadata), RFC 9728 (OAuth 2.0 Protected Resource Metadata), and RFC
7517 (JWKS). Registered with NO prefix in main.py: these have to live
at a fixed, well-known root path by spec, not wherever this platform
happens to prefix its own APIs (contrast with api/oauth.py's actual
OAuth endpoints, which the metadata below points at under /api/v1/oauth).

A real MCP client discovers this platform entirely from these two
documents plus the JWKS — no hardcoded endpoint URLs, no custom client
code to point it here.
"""

from fastapi import APIRouter

from app.core.config import settings
from app.core.jwks import get_jwks
from app.core.constants import PermissionScope
from app.schemas.oauth import AuthorizationServerMetadata, ProtectedResourceMetadata

router = APIRouter()


@router.get("/.well-known/oauth-authorization-server", response_model=AuthorizationServerMetadata)
async def authorization_server_metadata():
    base = settings.PUBLIC_BASE_URL
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/api/v1/oauth/authorize",
        "token_endpoint": f"{base}/api/v1/oauth/token",
        "registration_endpoint": f"{base}/api/v1/oauth/register",
        "jwks_uri": f"{base}/.well-known/jwks.json",
        "scopes_supported": [s.value for s in PermissionScope],
    }


@router.get("/.well-known/oauth-protected-resource", response_model=ProtectedResourceMetadata)
async def protected_resource_metadata():
    base = settings.PUBLIC_BASE_URL
    return {
        # The MCP proxy itself — every mcp_server_id an agent can be
        # bound to sits behind this one resource path, distinguished by
        # the RFC 8707 resource= parameter (the specific mcp_server_id),
        # not by a different protected-resource identifier per server.
        "resource": f"{base}/api/v1/mcp",
        "authorization_servers": [base],
        "scopes_supported": [s.value for s in PermissionScope],
    }


@router.get("/.well-known/jwks.json")
async def jwks():
    return get_jwks()
