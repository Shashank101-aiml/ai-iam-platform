"""
Full agent credential lifecycle over real HTTP: issue a key, exchange
it for a JWT, use that JWT against a genuinely agent-authenticated
route, then confirm a revoked key can no longer be exchanged.

Before Slice 4, none of this path actually worked:
- token/exchange passed org_id="lookup_from_key" into a full org-scoped
  scan, so it always matched zero rows — no agent could ever get a JWT.
- AgentAuthMiddleware's path list included "/api/v1/agents/", so the
  key-issuance call in step 1 (an operator route) would itself have
  401'd before ever reaching the handler.

OPA and the actual MCP tool call are mocked at the edges — this test is
about the credential path reaching the handler, not about OPA policy
evaluation or a real external tool call (those are covered, or will be,
by test_mcp_proxy.py and later slices).
"""

from unittest.mock import patch

import pytest
from httpx import AsyncClient

from app.models.agent import Agent
from app.services.mcp_proxy_service import mcp_proxy_service


@pytest.mark.asyncio
async def test_full_credential_exchange_path_reaches_agent_authenticated_route(
    client: AsyncClient, operator_token: str, test_agent: Agent
):
    # 1. Issue a key for the agent (operator-authenticated).
    issue_resp = await client.post(
        f"/api/v1/agents/{test_agent.id}/keys",
        headers={"Authorization": operator_token},
        json={"scopes": ["tool:execute"], "ttl_days": 30},
    )
    assert issue_resp.status_code == 201, issue_resp.text
    key_data = issue_resp.json()
    compound_credential = f"{key_data['key_id']}:{key_data['plaintext_key']}"

    # 2. Exchange the key for an agent JWT — no auth header at all; this
    # request IS how an agent authenticates for the very first time.
    exchange_resp = await client.post(
        "/api/v1/token/exchange",
        json={"grant_type": "api_key", "credential": compound_credential},
    )
    assert exchange_resp.status_code == 200, exchange_resp.text
    token_data = exchange_resp.json()
    # expires_in must be a relative duration (<=900s, matching
    # AGENT_ACCESS_TOKEN_EXPIRE_MINUTES=15), not the raw exp epoch
    # timestamp the old `... and 0 or 0` expression produced.
    assert 0 < token_data["expires_in"] <= 900
    agent_token = f"Bearer {token_data['access_token']}"

    # 3. Use that JWT against a genuinely agent-authenticated route.
    with patch(
        "app.services.mcp_proxy_service.check_permission", return_value=True
    ), patch.object(
        mcp_proxy_service, "_call_mcp_server", return_value=({"result": "ok"}, None)
    ):
        response = await client.post(
            "/api/v1/mcp/tools/search_web",
            headers={"Authorization": agent_token},
            json={
                "mcp_server_id": "srv-1",
                "arguments": {"q": "test"},
            },
        )
    assert response.status_code == 200, response.text
    assert response.json()["result"] == {"result": "ok"}

    # 4. Revoke the key — further *exchanges* with it must fail. This
    # does not (and isn't meant to) invalidate the JWT already issued in
    # step 2 before the revocation — agent JWTs are stateless, and
    # _check_jti_revoked always returning False is a separate, already
    # tracked gap, not something this path is responsible for closing.
    revoke_resp = await client.delete(
        f"/api/v1/keys/{key_data['key_id']}",
        headers={"Authorization": operator_token},
    )
    assert revoke_resp.status_code == 204

    second_exchange_resp = await client.post(
        "/api/v1/token/exchange",
        json={"grant_type": "api_key", "credential": compound_credential},
    )
    assert second_exchange_resp.status_code == 401


@pytest.mark.asyncio
async def test_bare_key_without_key_id_prefix_is_rejected(
    client: AsyncClient, operator_token: str, test_agent: Agent
):
    """
    token/exchange has no org_id to scope a lookup by, so it must
    refuse a bare "aiiam_..." key (no "kid_xxx:" prefix) rather than
    attempt an unscoped scan across every organization's keys.
    """
    issue_resp = await client.post(
        f"/api/v1/agents/{test_agent.id}/keys",
        headers={"Authorization": operator_token},
        json={"scopes": ["tool:execute"], "ttl_days": 30},
    )
    assert issue_resp.status_code == 201, issue_resp.text
    bare_plaintext_key = issue_resp.json()["plaintext_key"]

    response = await client.post(
        "/api/v1/token/exchange",
        json={"grant_type": "api_key", "credential": bare_plaintext_key},
    )
    assert response.status_code == 401
