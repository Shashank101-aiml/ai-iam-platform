"""
Automated tests for Multi-Hop Delegation scope attenuation and depth enforcement.
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.organization import Organization
from app.models.agent import Agent
from app.services.delegation_service import delegation_service
from app.core.constants import AgentStatus
from fastapi import HTTPException


@pytest.mark.asyncio
async def test_delegation_scope_attenuation_enforced(
    db_session: AsyncSession, test_org: Organization, test_agent: Agent
):
    """Verifies that a delegatee agent cannot be granted scopes that exceed the delegator's scopes."""
    import uuid
    # Create child agent
    child = Agent(
        id=str(uuid.uuid4()),
        org_id=test_org.id,
        name="Sub Agent",
        status=AgentStatus.ACTIVE,
        allowed_scopes=["audit:read", "threat:mitigate", "super:admin"],
    )
    db_session.add(child)
    await db_session.commit()

    # Attempt to delegate "super:admin" from test_agent (who only has ["audit:read", "threat:mitigate", "tool:execute"])
    with pytest.raises(HTTPException) as exc_info:
        await delegation_service.delegate(
            db_session,
            delegating_agent_id=test_agent.id,
            delegatee_agent_id=child.id,
            org_id=test_org.id,
            requested_scopes=["audit:read", "super:admin"],
            parent_trace_id="del-trace-1",
            current_depth=0,
        )
    assert exc_info.value.status_code == 422
    assert "Requested scopes exceed delegator's active scopes" in str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_max_delegation_depth_ceiling(
    db_session: AsyncSession, test_org: Organization, test_agent: Agent
):
    """Verifies that delegation depth exceeding MAX_DELEGATION_DEPTH is blocked."""
    import uuid
    child = Agent(
        id=str(uuid.uuid4()),
        org_id=test_org.id,
        name="Deep Sub Agent",
        status=AgentStatus.ACTIVE,
        allowed_scopes=["audit:read"],
    )
    db_session.add(child)
    await db_session.commit()

    # Attempt to delegate with current_depth=3 (assuming max is 3)
    with pytest.raises(HTTPException) as exc_info:
        await delegation_service.delegate(
            db_session,
            delegating_agent_id=test_agent.id,
            delegatee_agent_id=child.id,
            org_id=test_org.id,
            requested_scopes=["audit:read"],
            parent_trace_id="del-trace-2",
            current_depth=3,
        )
    assert exc_info.value.status_code == 403
    assert "exceeds maximum allowed depth" in str(exc_info.value.detail)
