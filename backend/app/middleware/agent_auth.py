"""
Agent Authentication Middleware.

Validates agent JWTs on every request:
1. Extract token from Authorization: Bearer <token>
2. Quick jti extract (unverified) to check revocation index first
3. Full RS256 signature verification
4. Delegation depth check
5. Bind identity to request state for downstream use

Why check jti BEFORE full verification?
Full RS256 verification involves crypto operations. If the token is
already revoked, we can reject it cheaply with a DB/cache lookup
before doing the expensive crypto. In high-traffic systems this matters.

Note: This middleware handles AGENT tokens only.
Human operator tokens are handled by the auth dependency in api/auth.py.
"""

from typing import Optional
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from jose import JWTError, ExpiredSignatureError
from jose.exceptions import JWTClaimsError

from app.core.jwt import verify_agent_token, extract_jti
from app.core.config import settings
from app.core.revocation import is_revoked, RevocationCheckUnavailable


# Routes that don't require agent authentication
EXCLUDED_PATHS = {
    "/health",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/organizations",  # Org creation (bootstrap)
    # OAuth/MCP discovery — RFC 8414/9728/7517 all require these to be
    # fetchable with no credentials at all, by definition (a client
    # hasn't obtained anything to authenticate WITH yet at this point).
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/.well-known/jwks.json",
    # /api/v1/oauth/token is secured by PKCE, not a bearer token — the
    # client presenting a code_verifier has no agent JWT yet either
    # (this IS how it gets one). /register and /authorize are already
    # excluded from agent-auth by _requires_agent_auth's prefix list
    # below not matching them at all; they're operator-gated
    # (Depends(get_current_user)) instead, a separate mechanism.
    "/api/v1/oauth/token",
}


class AgentAuthMiddleware(BaseHTTPMiddleware):
    """
    Request-level middleware that validates agent JWTs.
    Sets request.state.agent_identity on success.
    """

    async def dispatch(self, request: Request, call_next):
        # Skip non-agent routes
        if request.url.path in EXCLUDED_PATHS:
            return await call_next(request)

        # Only enforce on agent-facing API paths
        if not self._requires_agent_auth(request.url.path):
            return await call_next(request)

        token = self._extract_bearer_token(request)
        if not token:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"error": "missing_token", "detail": "Authorization header required"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            identity = await self._validate_token(token, request)
        except HTTPException as e:
            return JSONResponse(
                status_code=e.status_code,
                content=e.detail,
            )

        # Bind to request state — accessible in route handlers via request.state.agent
        request.state.agent = identity
        return await call_next(request)

    async def _validate_token(self, token: str, request: Request) -> dict:
        """Full token validation pipeline."""

        # Step 1: Quick jti extract (no crypto yet)
        jti = extract_jti(token)
        if not jti:
            raise HTTPException(
                status_code=401,
                detail={"error": "invalid_token", "detail": "Token missing jti claim"}
            )

        # Step 2: JTI revocation check
        revoked = await self._check_jti_revoked(jti)
        if revoked:
            raise HTTPException(
                status_code=401,
                detail={"error": "token_revoked", "detail": "Token has been revoked"}
            )

        # Step 3: Full RS256 verification + claims validation
        try:
            payload = verify_agent_token(token)
        except ExpiredSignatureError:
            raise HTTPException(
                status_code=401,
                detail={"error": "token_expired", "detail": "Agent token has expired"}
            )
        except JWTClaimsError as e:
            raise HTTPException(
                status_code=401,
                detail={"error": "invalid_claims", "detail": str(e)}
            )
        except JWTError as e:
            raise HTTPException(
                status_code=401,
                detail={"error": "invalid_token", "detail": "Token verification failed"}
            )

        # Step 4: Delegation depth enforcement
        depth = payload.get("delegation_depth", 0)
        if depth > settings.MAX_DELEGATION_DEPTH:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "delegation_depth_exceeded",
                    "depth": depth,
                    "max": settings.MAX_DELEGATION_DEPTH,
                }
            )

        return {
            "agent_id": payload["agent_id"],
            "org_id": payload["org_id"],
            "scopes": payload.get("scopes", []),
            "jti": jti,
            "causal_trace_id": payload.get("causal_trace_id"),
            "delegation_depth": depth,
            "parent_agent_id": payload.get("parent_agent_id"),
            "token_type": payload.get("token_type", "access"),
            # RFC 8707 Resource Indicator, if this token was minted via
            # the OAuth authorization_code flow with a resource=
            # parameter — see core/jwt.py's create_agent_access_token.
            "resource": payload.get("resource"),
            # RFC 9396 authorization_details, if this token was minted
            # task-scoped to specific (mcp_server_id, tool_name) pairs —
            # see core/jwt.py's authorization_details claim.
            "authorization_details": payload.get("authorization_details"),
            # Which human operator's authority this token carries, if
            # any — see core/jwt.py's on_behalf_of claim and
            # agent_service.resolve_on_behalf_of.
            "on_behalf_of": payload.get("on_behalf_of"),
        }

    async def _check_jti_revoked(self, jti: str) -> bool:
        """
        Check if a JTI has been revoked via the Redis-backed revocation
        index (see core/revocation.py). Fails closed: if the index can't
        be reached at all, that's treated as a denial too — see
        RevocationCheckUnavailable's docstring for why this doesn't
        just silently return False instead.
        """
        try:
            return await is_revoked(jti)
        except RevocationCheckUnavailable as e:
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "revocation_check_unavailable",
                    "detail": f"Cannot verify token has not been revoked: {e}",
                },
            )

    def _extract_bearer_token(self, request: Request) -> Optional[str]:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:]
        return None

    def _requires_agent_auth(self, path: str) -> bool:
        """
        Determine if a path requires agent auth vs human auth.

        Only the two routes actually declared with
        Depends(get_current_agent_state) belong here — everything else
        under /api/v1/agents/, /api/v1/mcp/, and /api/v1/token is
        operator-facing (Depends(get_current_user)) or intentionally
        open (token exchange, which is how an agent gets its first JWT
        at all). A broader prefix match here — "/api/v1/agents/" in
        particular — silently 401s every real operator request to
        agent lifecycle routes (activate/suspend/decommission/get/keys)
        before get_current_user ever runs, since this middleware sits
        in front of it and demands an agent RS256 JWT instead.
        """
        agent_paths = [
            "/api/v1/mcp/tools/",
            "/api/v1/token/delegate",
        ]
        return any(path.startswith(p) for p in agent_paths)
