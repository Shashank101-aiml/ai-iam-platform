"""
Automated tests for multi-hop delegation: scope attenuation, depth
enforcement, and cycle detection.

Before Slice 5, delegation_service.delegate() always validated against a
freshly-constructed empty DelegationChain(), regardless of how many real
hops actually preceded the call — depth limits and cycle detection were
no-ops. These tests build genuine multi-hop chains through the database
(via repeated delegate() calls, threading each hop's real grant_id/jti
into the next) rather than asserting against a caller-supplied depth
parameter, so a passing test here means the actual persisted lineage is
what's being checked, not a number the caller could have claimed.
"""

import uuid

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import AgentStatus
from app.core.config import settings
from app.models.agent import Agent
from app.models.organization import Organization
from app.services.delegation_service import delegation_service


async def _make_agent(db_session: AsyncSession, org: Organization, name: str, scopes: list[str]) -> Agent:
    agent = Agent(
        id=str(uuid.uuid4()),
        org_id=org.id,
        name=name,
        status=AgentStatus.ACTIVE,
        allowed_scopes=scopes,
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


@pytest.mark.asyncio
async def test_delegation_scope_attenuation_enforced(
    db_session: AsyncSession, test_org: Organization, test_agent: Agent
):
    """A root agent cannot delegate a scope it doesn't hold."""
    child = await _make_agent(
        db_session, test_org, "Sub Agent", ["audit:read", "threat:mitigate", "super:admin"]
    )

    # test_agent's own allowed_scopes (its "verified token scopes" here)
    # are ["audit:read", "threat:mitigate", "tool:execute"] — no "super:admin".
    with pytest.raises(HTTPException) as exc_info:
        await delegation_service.delegate(
            db_session,
            delegating_agent_id=test_agent.id,
            delegatee_agent_id=child.id,
            org_id=test_org.id,
            requested_scopes=["audit:read", "super:admin"],
            delegating_agent_verified_scopes=test_agent.allowed_scopes,
            parent_trace_id="del-trace-scope",
        )
    assert exc_info.value.status_code == 422
    assert "Requested scopes exceed delegator's active scopes" in str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_stale_token_cannot_exceed_current_allowed_scopes(
    db_session: AsyncSession, test_org: Organization, test_agent: Agent
):
    """
    Defense in depth: even if a caller's verified-token scopes somehow
    claimed more than the agent is CURRENTLY allowed (e.g. a long-lived
    token whose agent had its allowed_scopes tightened since), the
    intersection with the agent's live allowed_scopes is the real
    ceiling — not the token's claim alone.
    """
    child = await _make_agent(db_session, test_org, "Sub Agent 2", ["audit:read"])

    with pytest.raises(HTTPException) as exc_info:
        await delegation_service.delegate(
            db_session,
            delegating_agent_id=test_agent.id,
            delegatee_agent_id=child.id,
            org_id=test_org.id,
            requested_scopes=["audit:read", "agent:delegate"],
            # Claims a scope test_agent.allowed_scopes doesn't actually have.
            delegating_agent_verified_scopes=test_agent.allowed_scopes + ["agent:delegate"],
            parent_trace_id="del-trace-stale",
        )
    assert exc_info.value.status_code == 422
    assert "Requested scopes exceed delegator's active scopes" in str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_multi_hop_chain_attenuates_and_persists_lineage(
    db_session: AsyncSession, test_org: Organization
):
    """
    A(read, execute, delegate) -> B(read, execute) -> C(read).
    Each hop narrows correctly, and B — which was only ever granted
    [read, execute] — cannot grant "delegate" to C even though A had it,
    because B's OWN verified scopes at that point don't include it.
    """
    agent_a = await _make_agent(db_session, test_org, "Root A", ["read", "execute", "delegate"])
    agent_b = await _make_agent(db_session, test_org, "Mid B", ["read", "execute"])
    agent_c = await _make_agent(db_session, test_org, "Leaf C", ["read"])

    grant_ab = await delegation_service.delegate(
        db_session,
        delegating_agent_id=agent_a.id,
        delegatee_agent_id=agent_b.id,
        org_id=test_org.id,
        requested_scopes=["read", "execute"],
        delegating_agent_verified_scopes=agent_a.allowed_scopes,
        parent_trace_id="del-trace-multihop",
    )
    assert grant_ab["delegation_depth"] == 1
    assert set(grant_ab["scopes"]) == {"read", "execute"}

    # B attempts to pass along "delegate" too — B's own verified scopes
    # (what its just-issued token actually carries) don't include it.
    with pytest.raises(HTTPException) as exc_info:
        await delegation_service.delegate(
            db_session,
            delegating_agent_id=agent_b.id,
            delegatee_agent_id=agent_c.id,
            org_id=test_org.id,
            requested_scopes=["read", "delegate"],
            delegating_agent_verified_scopes=grant_ab["scopes"],
            delegating_agent_jti=grant_ab["jti"],
            parent_trace_id="del-trace-multihop",
        )
    assert exc_info.value.status_code == 422

    grant_bc = await delegation_service.delegate(
        db_session,
        delegating_agent_id=agent_b.id,
        delegatee_agent_id=agent_c.id,
        org_id=test_org.id,
        requested_scopes=["read"],
        delegating_agent_verified_scopes=grant_ab["scopes"],
        delegating_agent_jti=grant_ab["jti"],
        parent_trace_id="del-trace-multihop",
    )
    assert grant_bc["delegation_depth"] == 2
    assert set(grant_bc["scopes"]) == {"read"}
    assert grant_bc["grant"].parent_grant_id == grant_ab["grant"].id


@pytest.mark.asyncio
async def test_cycle_detection_rejects_return_to_ancestor(
    db_session: AsyncSession, test_org: Organization
):
    """A -> B -> C, then C attempts to delegate back to A. Rejected as a cycle."""
    agent_a = await _make_agent(db_session, test_org, "Cycle Root A", ["read"])
    agent_b = await _make_agent(db_session, test_org, "Cycle Mid B", ["read"])
    agent_c = await _make_agent(db_session, test_org, "Cycle Leaf C", ["read"])

    grant_ab = await delegation_service.delegate(
        db_session,
        delegating_agent_id=agent_a.id,
        delegatee_agent_id=agent_b.id,
        org_id=test_org.id,
        requested_scopes=["read"],
        delegating_agent_verified_scopes=agent_a.allowed_scopes,
        parent_trace_id="del-trace-cycle",
    )
    grant_bc = await delegation_service.delegate(
        db_session,
        delegating_agent_id=agent_b.id,
        delegatee_agent_id=agent_c.id,
        org_id=test_org.id,
        requested_scopes=["read"],
        delegating_agent_verified_scopes=grant_ab["scopes"],
        delegating_agent_jti=grant_ab["jti"],
        parent_trace_id="del-trace-cycle",
    )

    with pytest.raises(HTTPException) as exc_info:
        await delegation_service.delegate(
            db_session,
            delegating_agent_id=agent_c.id,
            delegatee_agent_id=agent_a.id,
            org_id=test_org.id,
            requested_scopes=["read"],
            delegating_agent_verified_scopes=grant_bc["scopes"],
            delegating_agent_jti=grant_bc["jti"],
            parent_trace_id="del-trace-cycle",
        )
    assert exc_info.value.status_code == 403
    assert "cycle detected" in str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_max_delegation_depth_ceiling(
    db_session: AsyncSession, test_org: Organization, test_agent: Agent
):
    """
    A real chain built one hop at a time up to MAX_DELEGATION_DEPTH,
    then one more hop attempted — rejected, not because a parameter said
    so, but because that many DelegationGrant rows genuinely exist.
    """
    scopes = ["audit:read"]
    delegating_agent = test_agent
    delegating_scopes = test_agent.allowed_scopes
    delegating_jti = None
    parent_trace_id = "del-trace-depth"

    for hop in range(settings.MAX_DELEGATION_DEPTH):
        child = await _make_agent(db_session, test_org, f"Depth Agent {hop}", scopes)
        result = await delegation_service.delegate(
            db_session,
            delegating_agent_id=delegating_agent.id,
            delegatee_agent_id=child.id,
            org_id=test_org.id,
            requested_scopes=scopes,
            delegating_agent_verified_scopes=delegating_scopes,
            delegating_agent_jti=delegating_jti,
            parent_trace_id=parent_trace_id,
        )
        assert result["delegation_depth"] == hop + 1
        delegating_agent = child
        delegating_scopes = result["scopes"]
        delegating_jti = result["jti"]

    # One more hop pushes depth past MAX_DELEGATION_DEPTH.
    one_too_many = await _make_agent(db_session, test_org, "Depth Agent Overflow", scopes)
    with pytest.raises(HTTPException) as exc_info:
        await delegation_service.delegate(
            db_session,
            delegating_agent_id=delegating_agent.id,
            delegatee_agent_id=one_too_many.id,
            org_id=test_org.id,
            requested_scopes=scopes,
            delegating_agent_verified_scopes=delegating_scopes,
            delegating_agent_jti=delegating_jti,
            parent_trace_id=parent_trace_id,
        )
    assert exc_info.value.status_code == 403
    assert "exceeds maximum allowed depth" in str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_delegation_to_self_rejected(
    db_session: AsyncSession, test_org: Organization, test_agent: Agent
):
    with pytest.raises(HTTPException) as exc_info:
        await delegation_service.delegate(
            db_session,
            delegating_agent_id=test_agent.id,
            delegatee_agent_id=test_agent.id,
            org_id=test_org.id,
            requested_scopes=["audit:read"],
            delegating_agent_verified_scopes=test_agent.allowed_scopes,
            parent_trace_id="del-trace-self",
        )
    assert exc_info.value.status_code == 403
    assert "cannot delegate to itself" in str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_delegation_through_revoked_grant_rejected(
    db_session: AsyncSession, test_org: Organization
):
    """
    Once a grant is revoked, the agent it authorized can no longer
    delegate further through it — _load_chain refuses to build a chain
    through a revoked link, even though the JWT itself would still
    verify cryptographically until it expires (that gap is Slice 9's).
    """
    agent_a = await _make_agent(db_session, test_org, "Revoke Root A", ["read"])
    agent_b = await _make_agent(db_session, test_org, "Revoke Mid B", ["read"])
    agent_c = await _make_agent(db_session, test_org, "Revoke Leaf C", ["read"])

    grant_ab = await delegation_service.delegate(
        db_session,
        delegating_agent_id=agent_a.id,
        delegatee_agent_id=agent_b.id,
        org_id=test_org.id,
        requested_scopes=["read"],
        delegating_agent_verified_scopes=agent_a.allowed_scopes,
        parent_trace_id="del-trace-revoke",
    )

    await delegation_service.revoke_grant(
        db_session,
        grant_id=grant_ab["grant"].id,
        org_id=test_org.id,
        actor_id="test-operator",
        reason="testing cascading rejection",
    )

    with pytest.raises(HTTPException) as exc_info:
        await delegation_service.delegate(
            db_session,
            delegating_agent_id=agent_b.id,
            delegatee_agent_id=agent_c.id,
            org_id=test_org.id,
            requested_scopes=["read"],
            delegating_agent_verified_scopes=grant_ab["scopes"],
            delegating_agent_jti=grant_ab["jti"],
            parent_trace_id="del-trace-revoke",
        )
    assert exc_info.value.status_code == 403
    assert "has been revoked" in str(exc_info.value.detail)
