"""
Overview counts Pydantic v2 schema — the live numbers on the dashboard's
navigation badges.
"""

from pydantic import BaseModel


class OverviewCounts(BaseModel):
    agents: int
    sub_agents: int
    audit_entries: int
    mcp_calls: int
    mcp_blocked: int
