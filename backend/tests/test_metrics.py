"""
Slice 14 tests: domain Prometheus metrics.

Proves /metrics actually serves the domain counters/histograms in
core/metrics.py (not just the instrumentator's generic per-route HTTP
histograms), and that a triggering action really moves one of them —
not just that the metric name appears in the exposition format at 0
from having been declared and never touched.
"""

import pytest
from unittest.mock import patch
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import PermissionDeniedError
from app.models.agent import Agent
from app.models.organization import Organization
from app.services.mcp_proxy_service import mcp_proxy_service


@pytest.mark.asyncio
async def test_metrics_endpoint_serves_domain_metrics(client: AsyncClient):
    resp = await client.get("/metrics")
    assert resp.status_code == 200
    body = resp.text
    assert "aiiam_mcp_tool_denials_total" in body
    assert "aiiam_delegation_depth" in body
    assert "aiiam_credential_rotations_total" in body
    assert "aiiam_audit_chain_verify_duration_seconds" in body


@pytest.mark.asyncio
async def test_denial_counter_increments_on_a_real_block(
    client: AsyncClient, db_session: AsyncSession, test_org: Organization, test_agent: Agent,
):
    before = _denial_count((await client.get("/metrics")).text)

    with patch("app.services.mcp_proxy_service.check_permission") as mock_check:
        mock_check.side_effect = PermissionDeniedError("denied for metrics test")
        with pytest.raises(HTTPException):
            await mcp_proxy_service.execute_tool(
                db_session,
                agent_id=test_agent.id,
                org_id=test_org.id,
                mcp_server_id="srv-1",
                tool_name="search_web",
                tool_args={},
                token_scopes=["tool:execute"],
                causal_trace_id="metrics-test-trace",
            )

    after = _denial_count((await client.get("/metrics")).text)
    assert after > before


def _denial_count(metrics_text: str) -> float:
    total = 0.0
    for line in metrics_text.splitlines():
        if line.startswith("aiiam_mcp_tool_denials_total{"):
            total += float(line.rsplit(" ", 1)[-1])
    return total
