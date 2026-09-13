"""
OAuth 2.1 Authorization Server logic: Dynamic Client Registration
(RFC 7591), the authorization_code + PKCE grant (OAuth 2.1 §4.1, PKCE
mandatory for every client), and RFC 8707 Resource Indicators.

This platform IS the Authorization Server — it already mints its own
RS256 agent tokens (core/jwt.py) — rather than a second AS bolted on in
front of the existing bespoke /token/exchange path. The authorization
code itself lives in Redis (app.core.revocation's client, a distinct
key namespace: oauth_code:{code}), not Postgres: it's a single-use,
120-second-lived value by design, exactly the shape Redis's GETDEL
(atomic fetch-and-delete, enforcing single-use without a separate
transaction) already exists for.

Who is the "resource owner" granting consent here? In a human-facing
OAuth flow it's the end user; in this agent-identity platform it's the
OPERATOR, authorizing a registered client to obtain a token that acts
AS one of their org's agents. /authorize therefore requires the
operator's own authentication (Depends(get_current_user), same as
every other operator-facing route) — the authenticated request IS the
consent, since this project has no rendered browser consent screen to
build a UI layer for. That's a deliberate, narrower-than-full-spec
scope decision, documented here rather than silently assumed.
"""

import json
import secrets
import uuid
from typing import Optional
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException

from app.core.config import settings
from app.core.security import verify_pkce_challenge
from app.core.jwt import create_agent_access_token
from app.core.revocation import get_redis_client, track_issued_jti
from app.core.constants import PermissionScope, AgentStatus
from app.models.oauth_client import OAuthClient
from app.repositories.oauth_client_repo import oauth_client_repo
from app.repositories.agent_repo import agent_repo


def _validate_redirect_uris(redirect_uris: list[str], application_type: str) -> None:
    """
    RFC 8252 (OAuth 2.0 for Native Apps): a "web" client's redirect_uris
    must be https — no exceptions, since a plain-http redirect on a
    non-loopback host can be intercepted. A "native" (desktop/CLI)
    client may ALSO use a loopback http redirect
    (http://127.0.0.1:<any-port>/... or http://localhost:<any-port>/...
    — the port varies per launch, so no fixed port is required) or a
    private-use URI scheme (myapp://callback) — both are the reason
    application_type exists as a registration field at all.
    """
    for uri in redirect_uris:
        parsed = urlparse(uri)
        if application_type == "web":
            if parsed.scheme != "https":
                raise ValueError(
                    f"web clients require https redirect_uris; got '{uri}'"
                )
        else:  # native
            if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
                raise ValueError(
                    f"native clients may use a loopback http redirect_uri "
                    f"(http://127.0.0.1:<port>/... or http://localhost:<port>/...) "
                    f"or a private-use URI scheme, not plain http on a "
                    f"non-loopback host; got '{uri}'"
                )


async def register_client(
    db: AsyncSession,
    *,
    org_id: str,
    client_name: str,
    redirect_uris: list[str],
    application_type: str,
    requested_grant_types: Optional[list[str]],
    requested_response_types: Optional[list[str]],
    raw_metadata: dict,
) -> OAuthClient:
    """Dynamic Client Registration (RFC 7591) — see module docstring for why this is operator-gated, not anonymous."""
    _validate_redirect_uris(redirect_uris, application_type)

    # This AS supports exactly one grant/response type combination today
    # — authorization_code + PKCE. A client requesting anything else is
    # rejected at registration rather than silently granted a narrower
    # set than it asked for.
    if requested_grant_types and requested_grant_types != ["authorization_code"]:
        raise ValueError(
            f"only the authorization_code grant type is supported; got {requested_grant_types}"
        )
    if requested_response_types and requested_response_types != ["code"]:
        raise ValueError(
            f"only the 'code' response type is supported; got {requested_response_types}"
        )

    client = OAuthClient(
        id=str(uuid.uuid4()),
        org_id=org_id,
        client_id=f"mcpc_{secrets.token_hex(16)}",
        client_name=client_name,
        application_type=application_type,
        redirect_uris=redirect_uris,
        grant_types=["authorization_code"],
        response_types=["code"],
        token_endpoint_auth_method="none",
        raw_metadata=raw_metadata,
    )
    db.add(client)
    await db.flush()
    await db.refresh(client)
    return client


async def build_authorization_redirect(
    db: AsyncSession,
    *,
    client_id: str,
    redirect_uri: str,
    response_type: str,
    code_challenge: str,
    code_challenge_method: str,
    state: Optional[str],
    scope: str,
    resource: Optional[str],
    agent_id: str,
    org_id: str,
) -> str:
    """
    Validate an /authorize request and, on success, return the full
    redirect_uri (with code/state/iss query params) the caller should
    302 to. Raises HTTPException on any validation failure — the caller
    decides whether that's safe to redirect (only once client_id AND
    redirect_uri are both confirmed registered together) or must be
    shown directly instead, per OAuth 2.1 §4.1.2.1's guidance that an
    invalid/mismatched redirect_uri must NOT be used to deliver the
    error.
    """
    client = await oauth_client_repo.get_by_client_id(db, client_id)
    if not client or client.org_id != org_id:
        raise HTTPException(status_code=400, detail="Unknown client_id")
    if redirect_uri not in client.redirect_uris:
        raise HTTPException(status_code=400, detail="redirect_uri is not registered for this client")

    # From here on, redirect_uri is confirmed to belong to this client —
    # any further error is safe to deliver via redirect (OAuth 2.1 §4.1.2.1).
    if response_type != "code":
        return _error_redirect(redirect_uri, state, "unsupported_response_type")
    if code_challenge_method != "S256":
        return _error_redirect(redirect_uri, state, "invalid_request", "code_challenge_method must be S256")
    if not code_challenge:
        return _error_redirect(redirect_uri, state, "invalid_request", "code_challenge is required")

    agent = await agent_repo.get_by_id_and_org(db, agent_id, org_id)
    if not agent:
        return _error_redirect(redirect_uri, state, "invalid_request", "agent_id not found in this organization")
    if agent.status != AgentStatus.ACTIVE:
        return _error_redirect(redirect_uri, state, "invalid_request", f"agent is {agent.status}, not ACTIVE")

    requested_scopes = scope.split() if scope else []
    invalid_scopes = set(requested_scopes) - set(agent.allowed_scopes or [])
    if invalid_scopes:
        return _error_redirect(redirect_uri, state, "invalid_scope", f"not permitted for this agent: {sorted(invalid_scopes)}")

    if resource is not None:
        bound_server_ids = {b.get("server_id") for b in (agent.mcp_bindings or [])}
        if resource not in bound_server_ids:
            return _error_redirect(redirect_uri, state, "invalid_target", f"agent is not bound to resource '{resource}'")

    code = secrets.token_urlsafe(32)
    code_data = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "agent_id": agent_id,
        "org_id": org_id,
        "scopes": requested_scopes,
        "resource": resource,
    }
    await get_redis_client().set(
        f"oauth_code:{code}",
        json.dumps(code_data),
        ex=settings.OAUTH_AUTHORIZATION_CODE_TTL_SECONDS,
    )

    params = f"code={code}"
    if state:
        params += f"&state={state}"
    # RFC 9207 — the AS's own issuer identifier in the redirect response,
    # so the client can detect an authorization-server mix-up (a
    # malicious or misconfigured second AS answering in this one's
    # place) before it ever exchanges the code.
    params += f"&iss={_issuer()}"
    separator = "&" if "?" in redirect_uri else "?"
    return f"{redirect_uri}{separator}{params}"


def _error_redirect(redirect_uri: str, state: Optional[str], error: str, description: Optional[str] = None) -> str:
    params = f"error={error}"
    if description:
        from urllib.parse import quote
        params += f"&error_description={quote(description)}"
    if state:
        params += f"&state={state}"
    separator = "&" if "?" in redirect_uri else "?"
    return f"{redirect_uri}{separator}{params}"


def _issuer() -> str:
    return settings.PUBLIC_BASE_URL


async def exchange_authorization_code(
    *,
    grant_type: str,
    code: str,
    redirect_uri: str,
    client_id: str,
    code_verifier: str,
    resource: Optional[str],
) -> dict:
    """
    Redeem a single-use authorization code for an agent access token.
    GETDEL makes the fetch-and-invalidate atomic — a code can never be
    redeemed twice, even under concurrent requests racing each other.
    """
    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail={"error": "unsupported_grant_type"})

    raw = await get_redis_client().getdel(f"oauth_code:{code}")
    if raw is None:
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "code is invalid, expired, or already used"})

    code_data = json.loads(raw)

    if code_data["client_id"] != client_id:
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "client_id does not match the one the code was issued to"})
    if code_data["redirect_uri"] != redirect_uri:
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "redirect_uri does not match the one used at /authorize"})
    if not verify_pkce_challenge(code_verifier, code_data["code_challenge"]):
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "code_verifier does not match the code_challenge presented at /authorize"})

    bound_resource = code_data.get("resource")
    if bound_resource is not None and resource != bound_resource:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_target", "error_description": f"token request's resource must match the one authorized: '{bound_resource}'"},
        )

    scopes = []
    for s in code_data["scopes"]:
        try:
            scopes.append(PermissionScope(s))
        except ValueError:
            pass

    token_dict = create_agent_access_token(
        agent_id=code_data["agent_id"],
        org_id=code_data["org_id"],
        scopes=scopes,
        causal_trace_id=f"oauth:{uuid.uuid4()}",
        resource=bound_resource,
    )
    await track_issued_jti(f"agent:{code_data['agent_id']}:jtis", token_dict["jti"], token_dict["exp"])

    return {
        "access_token": token_dict["token"],
        "token_type": "bearer",
        "expires_in": token_dict["expires_in"],
        "scope": " ".join(code_data["scopes"]),
    }
