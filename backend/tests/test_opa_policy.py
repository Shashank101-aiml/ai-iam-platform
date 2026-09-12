"""
Tests against the REAL running OPA instance and the real authz.rego
policy — not the mocked check_permission that test_mcp_proxy.py
exercises elsewhere. Requires OPA_URL to point at a reachable OPA with
backend/policies/ loaded (docker-compose's opa service does this).

The fail-closed tests specifically prove something test_mcp_proxy.py's
mock-based test can't: that check_permission ITSELF denies when OPA is
genuinely unreachable, not just that the proxy handles a
PermissionDeniedError correctly once one is raised.
"""

import pytest

from app.core.config import settings
from app.core.permissions import check_permission, PermissionDeniedError


@pytest.mark.asyncio
async def test_check_permission_allows_real_policy_match():
    result = await check_permission(
        agent_id="agent-1",
        org_id="org-1",
        action="tool:execute",
        resource_type="mcp_tool",
        resource_id="search_web",
        token_scopes=["tool:execute"],
        delegation_depth=1,
    )
    assert result is True


@pytest.mark.asyncio
async def test_check_permission_denies_blocked_tool_via_real_policy():
    """authz.rego's blocked_tools set — a scope match alone isn't enough."""
    with pytest.raises(PermissionDeniedError):
        await check_permission(
            agent_id="agent-1",
            org_id="org-1",
            action="tool:execute",
            resource_type="mcp_tool",
            resource_id="drop_table",
            token_scopes=["tool:execute"],
            delegation_depth=1,
        )


@pytest.mark.asyncio
async def test_check_permission_denies_missing_scope_via_real_policy():
    with pytest.raises(PermissionDeniedError):
        await check_permission(
            agent_id="agent-1",
            org_id="org-1",
            action="tool:execute",
            resource_type="mcp_tool",
            resource_id="search_web",
            token_scopes=["audit:read"],  # doesn't include tool:execute
            delegation_depth=1,
        )


@pytest.mark.asyncio
async def test_check_permission_denies_depth_over_ceiling_via_real_policy():
    with pytest.raises(PermissionDeniedError):
        await check_permission(
            agent_id="agent-1",
            org_id="org-1",
            action="tool:execute",
            resource_type="mcp_tool",
            resource_id="search_web",
            token_scopes=["tool:execute"],
            delegation_depth=6,  # over MAX_DELEGATION_DEPTH=5
        )


@pytest.mark.asyncio
async def test_check_permission_fails_closed_when_opa_unreachable(monkeypatch):
    """
    The real check_permission, pointed at an address nothing is
    listening on, must deny rather than allow or raise something the
    caller doesn't already handle. This is what actually protects the
    platform if OPA crashes in production.

    (The sibling httpx.TimeoutException branch in check_permission is
    structurally identical — same raise PermissionDeniedError(...) — and
    isn't separately exercised here to avoid a slow/flaky test that
    depends on the environment's routing to a deliberately
    non-responding address actually timing out rather than erroring
    immediately.)
    """
    monkeypatch.setattr(settings, "OPA_URL", "http://127.0.0.1:1")
    with pytest.raises(PermissionDeniedError):
        await check_permission(
            agent_id="agent-1",
            org_id="org-1",
            action="tool:execute",
            resource_type="mcp_tool",
            resource_id="search_web",
            token_scopes=["tool:execute"],
            delegation_depth=1,
        )
