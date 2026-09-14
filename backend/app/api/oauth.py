"""
OAuth 2.1 / MCP resource-server compliance router.

- POST /register            Dynamic Client Registration (RFC 7591), operator-gated
- GET  /authorize            Authorization Code + PKCE grant, step 1 (operator-gated — see oauth_service's module docstring for what "consent" means here)
- POST /token                Authorization Code + PKCE grant, step 2 (public — PKCE is what secures this, not an Authorization header)

Discovery documents (.well-known/*) are a SEPARATE router with no
prefix — see well_known.py — because RFC 8414/9728 require them at a
fixed, root-level path, not wherever this platform happens to prefix
its own APIs.
"""

from fastapi import APIRouter, Depends, Query, Form, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse

from app.db.session import get_db
from app.schemas.oauth import (
    ClientRegistrationRequest,
    ClientRegistrationResponse,
    OAuthTokenResponse,
)
from app.services import oauth_service
from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter()


@router.post("/register", response_model=ClientRegistrationResponse, status_code=201)
async def register_client(
    reg_in: ClientRegistrationRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Dynamic Client Registration (RFC 7591). Operator-gated: RFC 7591 §3
    explicitly permits requiring an initial access token before
    registration, and an anonymous registration endpoint would have no
    organization to attribute the new client to in this multi-tenant
    platform.
    """
    try:
        client = await oauth_service.register_client(
            db,
            org_id=current_user.org_id,
            client_name=reg_in.client_name,
            redirect_uris=reg_in.redirect_uris,
            application_type=reg_in.application_type,
            requested_grant_types=reg_in.grant_types,
            requested_response_types=reg_in.response_types,
            raw_metadata=reg_in.model_dump(),
        )
    except ValueError as e:
        # RFC 7591 §3.2.2's error shape for a registration request the
        # server refuses to honor as submitted.
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_client_metadata", "error_description": str(e)},
        )
    await db.commit()
    return {
        "client_id": client.client_id,
        "client_id_issued_at": int(client.created_at.timestamp()),
        "client_name": client.client_name,
        "redirect_uris": client.redirect_uris,
        "application_type": client.application_type,
        "grant_types": client.grant_types,
        "response_types": client.response_types,
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
    }


@router.get("/authorize")
async def authorize(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    code_challenge: str = Query(...),
    code_challenge_method: str = Query(...),
    agent_id: str = Query(..., description="Which of the operator's org's agents this client is being authorized to act as"),
    scope: str = Query(""),
    resource: str | None = Query(None, description="RFC 8707 Resource Indicator — the mcp_server_id this token should be bound to"),
    tool_name: str | None = Query(None, description="RFC 9396 task-scoping — narrows the token to this ONE tool on `resource` (requires resource to also be set)"),
    state: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Authorization Code + PKCE grant, step 1. The authenticated operator
    IS the consent here (see oauth_service's module docstring) — there
    is no separate rendered consent screen. On success, 302s the
    user-agent back to the client's redirect_uri with a `code` (and
    `iss`, RFC 9207); on failure (once client_id/redirect_uri are
    confirmed to belong together), 302s back with an `error` instead of
    rendering a JSON error directly — matching what a browser-driven
    OAuth flow expects at this endpoint.
    """
    target = await oauth_service.build_authorization_redirect(
        db,
        client_id=client_id,
        redirect_uri=redirect_uri,
        response_type=response_type,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        state=state,
        scope=scope,
        resource=resource,
        tool_name=tool_name,
        agent_id=agent_id,
        org_id=current_user.org_id,
    )
    return RedirectResponse(url=target, status_code=302)


@router.post("/token", response_model=OAuthTokenResponse)
async def token(
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
    client_id: str = Form(...),
    code_verifier: str = Form(...),
    resource: str | None = Form(None),
    db: AsyncSession = Depends(get_db),
):
    """
    Authorization Code + PKCE grant, step 2. application/x-www-form-urlencoded
    body, per RFC 6749 §4.1.3 — not JSON, not query params: a real OAuth
    client library POSTs the token request this way, and this has to
    match it exactly for the "stock client, unmodified" exit criterion
    to mean anything.

    Deliberately takes no Authorization header and no
    Depends(get_current_user)/Depends(get_current_agent_state) — PKCE
    (code_verifier proving possession of whatever generated
    code_challenge at /authorize) is what secures this exchange for a
    public client, exactly as OAuth 2.1 intends; the client has no
    secret to present.
    """
    return await oauth_service.exchange_authorization_code(
        db,
        grant_type=grant_type,
        code=code,
        redirect_uri=redirect_uri,
        client_id=client_id,
        code_verifier=code_verifier,
        resource=resource,
    )
