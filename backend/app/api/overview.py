"""
Overview Router.
Org-scoped totals for the dashboard's navigation badges. Exists because no
other endpoint can supply them: /audit/logs and /mcp/sessions return only
the latest page (so a count taken from them would stick at the page size),
and /audit/verify replays the whole chain.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.overview import OverviewCounts
from app.repositories.agent_repo import agent_repo
from app.repositories.audit_repo import audit_repo
from app.repositories.mcp_session_repo import mcp_session_repo
from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter()


@router.get("/counts", response_model=OverviewCounts)
async def get_overview_counts(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Totals for the operator's own organization — never another tenant's."""
    agents, sub_agents = await agent_repo.count_by_org(db, current_user.org_id)
    mcp_calls, mcp_blocked = await mcp_session_repo.count_for_org(db, current_user.org_id)
    return OverviewCounts(
        agents=agents,
        sub_agents=sub_agents,
        audit_entries=await audit_repo.count_for_org(db, current_user.org_id),
        mcp_calls=mcp_calls,
        mcp_blocked=mcp_blocked,
    )
