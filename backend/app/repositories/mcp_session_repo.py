from typing import Optional, Sequence
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.mcp_session import McpSession
from app.repositories.base_repo import BaseRepository


class McpSessionRepository(BaseRepository[McpSession]):
    def __init__(self):
        super().__init__(McpSession)

    async def get_by_trace(
        self, db: AsyncSession, causal_trace_id: str, org_id: str
    ) -> Sequence[McpSession]:
        result = await db.execute(
            select(McpSession)
            .where(
                McpSession.causal_trace_id == causal_trace_id,
                McpSession.org_id == org_id,
            )
            .order_by(McpSession.created_at.asc())
        )
        return result.scalars().all()

    async def get_by_agent(
        self,
        db: AsyncSession,
        agent_id: str,
        org_id: str,
        limit: int = 100,
        tool_name: Optional[str] = None,
    ) -> Sequence[McpSession]:
        query = (
            select(McpSession)
            .where(McpSession.agent_id == agent_id, McpSession.org_id == org_id)
            .order_by(McpSession.created_at.desc())
            .limit(limit)
        )
        if tool_name:
            query = query.where(McpSession.tool_name == tool_name)
        result = await db.execute(query)
        return result.scalars().all()

    async def get_blocked_calls(
        self, db: AsyncSession, org_id: str, limit: int = 50
    ) -> Sequence[McpSession]:
        """Fetch policy-blocked tool calls — useful for security dashboards."""
        result = await db.execute(
            select(McpSession)
            .where(
                McpSession.org_id == org_id,
                McpSession.policy_decision == "blocked",
            )
            .order_by(McpSession.created_at.desc())
            .limit(limit)
        )
        return result.scalars().all()


mcp_session_repo = McpSessionRepository()
