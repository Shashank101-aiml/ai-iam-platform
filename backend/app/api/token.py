"""
Token Exchange & Delegation Router.
Exchanges API keys or SPIFFE credentials for short-lived RS256 JWTs (`verify_agent_token`)
and issues multi-hop delegation grants (`DelegationService.delegate`) with mathematical scope attenuation.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.token import TokenExchangeRequest, AgentJwtResponse, TokenInspectResponse
from app.schemas.delegation_grant import DelegationCreateRequest, DelegationTokenResponse
from app.services.api_key_service import api_key_service
from app.services.delegation_service import delegation_service
from app.core.jwt import create_agent_access_token, verify_agent_token, extract_jti
from app.core.constants import PermissionScope
from app.api.deps import get_current_agent_state

router = APIRouter()


@router.post("/exchange", response_model=AgentJwtResponse)
async def exchange_token(
    token_in: TokenExchangeRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Exchange an API key or SPIFFE token for a short-lived signed RS256 JWT.

    The credential must be in compound form ("kid_xxxxxxxx:aiiam_<hex>",
    the key_id from issuance followed by the plaintext secret) — this
    endpoint has no org_id to scope a lookup by, so it relies entirely
    on api_key_service.verify_key's O(1) key_id path. A bare
    "aiiam_..." key with no key_id prefix is rejected the same way an
    invalid key is: verify_key won't attempt an unscoped scan across
    every organization's keys.
    """
    if token_in.grant_type == "api_key":
        trace_id = token_in.causal_trace_id or "exchange:api_key"
        key_info = await api_key_service.verify_key(
            db,
            plaintext_key=token_in.credential,
            causal_trace_id=trace_id,
            source_ip=request.client.host if request.client else None,
        )
        if not key_info:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=(
                    "Invalid or expired API key. The credential must be in "
                    "the form 'kid_xxxxxxxx:aiiam_...' — both values are "
                    "returned together when the key is issued."
                ),
            )
        await db.commit()

        # Convert string scopes to PermissionScope enums where matching
        scopes = []
        for s in key_info["scopes"]:
            try:
                scopes.append(PermissionScope(s))
            except ValueError:
                pass

        token_dict = create_agent_access_token(
            agent_id=key_info["agent_id"],
            org_id=key_info["org_id"],
            scopes=scopes,
            causal_trace_id=trace_id,
            delegation_depth=0,
        )
        return {
            "access_token": token_dict["token"],
            "token_type": "bearer",
            "expires_in": token_dict["expires_in"],
            "jti": token_dict["jti"],
            "scopes": key_info["scopes"],
            "causal_trace_id": trace_id,
            "delegation_depth": 0,
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported grant_type: {token_in.grant_type}",
        )


@router.post("/delegate", response_model=DelegationTokenResponse)
async def create_delegation_grant(
    del_in: DelegationCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_agent: dict = Depends(get_current_agent_state),
):
    """
    Issue a multi-hop delegation grant and token.
    Enforces scope attenuation: requested_scopes must be a subset of the delegating agent's scopes.
    """
    grant_result = await delegation_service.delegate(
        db,
        delegating_agent_id=current_agent["agent_id"],
        delegatee_agent_id=del_in.delegatee_agent_id,
        org_id=current_agent["org_id"],
        requested_scopes=del_in.requested_scopes,
        parent_trace_id=del_in.causal_trace_id or current_agent.get("causal_trace_id", "delegate"),
        current_depth=current_agent.get("delegation_depth", 0),
        ttl_seconds=del_in.ttl_seconds,
    )
    await db.commit()
    return grant_result


@router.post("/inspect", response_model=TokenInspectResponse)
async def inspect_token(token: str):
    """Verify RS256 signature and decode JWT claims."""
    try:
        payload = verify_agent_token(token)
        return {"valid": True, "payload": payload}
    except Exception as e:
        return {"valid": False, "error": str(e)}
