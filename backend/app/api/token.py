"""
Token Exchange & Delegation Router.
Exchanges API keys or SPIFFE credentials for short-lived RS256 JWTs (`verify_agent_token`)
and issues multi-hop delegation grants (`DelegationService.delegate`) with mathematical scope attenuation.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.token import TokenExchangeRequest, AgentJwtResponse, TokenInspectResponse
from app.schemas.delegation_grant import (
    DelegationCreateRequest,
    DelegationTokenResponse,
    DelegationRevokeRequest,
    DelegationRevokeResponse,
)
from app.services.api_key_service import api_key_service
from app.services.delegation_service import delegation_service
from app.services.agent_service import agent_service
from app.core.jwt import create_agent_access_token, verify_agent_token, extract_jti
from app.core.constants import PermissionScope, AuditAction
from app.core.revocation import track_issued_jti
from app.repositories.agent_repo import agent_repo
from app.repositories.audit_repo import audit_repo
from app.api.deps import get_current_agent_state, get_current_user
from app.models.user import User

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

        agent = await agent_repo.get_by_id_and_org(db, key_info["agent_id"], key_info["org_id"])
        on_behalf_of = await agent_service.resolve_on_behalf_of(
            db, agent=agent, requested_scopes=key_info["scopes"]
        )

        token_dict = create_agent_access_token(
            agent_id=key_info["agent_id"],
            org_id=key_info["org_id"],
            scopes=scopes,
            causal_trace_id=trace_id,
            delegation_depth=0,
            on_behalf_of=on_behalf_of,
        )
        # Track this jti under both reverse indexes a cascade revoke
        # reads from — suspending/decommissioning the agent, or revoking
        # the API key it came from, needs to find this token to
        # blacklist it; JWTs are otherwise stateless.
        await track_issued_jti(
            f"agent:{key_info['agent_id']}:jtis", token_dict["jti"], token_dict["exp"]
        )
        await track_issued_jti(
            f"key:{key_info['key_id']}:jtis", token_dict["jti"], token_dict["exp"]
        )

        if on_behalf_of:
            # A separate entry, not folded into the CREDENTIAL_USED event
            # api_key_service already wrote above: that entry is
            # committed before on_behalf_of is even resolved (append-only
            # means it can't be edited after the fact), and audit_repo
            # entries are otherwise about actions, not JWT claims. This
            # is what get_trace()'s originating_operator field scans for.
            await audit_repo.append(
                org_id=key_info["org_id"],
                action=AuditAction.CREDENTIAL_USED,
                actor_type="agent",
                actor_id=key_info["agent_id"],
                agent_id=key_info["agent_id"],
                causal_trace_id=trace_id,
                outcome="success",
                details={"jti": token_dict["jti"], "on_behalf_of": on_behalf_of},
            )

        return {
            "access_token": token_dict["token"],
            "token_type": "bearer",
            "expires_in": token_dict["expires_in"],
            "jti": token_dict["jti"],
            "scopes": key_info["scopes"],
            "causal_trace_id": trace_id,
            "delegation_depth": 0,
            "on_behalf_of": on_behalf_of,
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
    Scopes and the delegation lineage both come from current_agent — the
    verified JWT payload AgentAuthMiddleware attached to this request —
    never from the request body. del_in only supplies what's being
    requested, not what the requester is trusted to hold.
    """
    grant_result = await delegation_service.delegate(
        db,
        delegating_agent_id=current_agent["agent_id"],
        delegatee_agent_id=del_in.delegatee_agent_id,
        org_id=current_agent["org_id"],
        requested_scopes=del_in.requested_scopes,
        delegating_agent_verified_scopes=current_agent.get("scopes", []),
        delegating_agent_jti=current_agent.get("jti"),
        parent_trace_id=del_in.causal_trace_id or current_agent.get("causal_trace_id"),
        ttl_seconds=del_in.ttl_seconds,
        on_behalf_of=current_agent.get("on_behalf_of"),
    )
    await db.commit()
    return grant_result


@router.post("/delegations/{grant_id}/revoke", response_model=DelegationRevokeResponse)
async def revoke_delegation_grant(
    grant_id: str,
    revoke_in: DelegationRevokeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Revoke a delegation grant immediately, cascading to every grant
    descending from it. Operator-facing (not agent-facing) — revocation
    is a governance action, same trust boundary as suspend/decommission
    in api/agents.py.
    """
    result = await delegation_service.revoke_grant(
        db,
        grant_id=grant_id,
        org_id=current_user.org_id,
        actor_id=f"user:{current_user.id}",
        reason=revoke_in.reason,
    )
    await db.commit()
    return result


@router.post("/inspect", response_model=TokenInspectResponse)
async def inspect_token(token: str):
    """Verify RS256 signature and decode JWT claims."""
    try:
        payload = verify_agent_token(token)
        return {"valid": True, "payload": payload}
    except Exception as e:
        return {"valid": False, "error": str(e)}
