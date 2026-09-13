"""
Slice 10 tests: MCP OAuth 2.1 resource-server compliance.

Covers discovery metadata shape, Dynamic Client Registration's
redirect_uri validation (RFC 8252's web-vs-native rule), and the full
authorization_code + PKCE grant end to end — including RFC 8707
Resource Indicator enforcement composing with the MCP proxy's existing
SSRF fix (a token minted bound to one mcp_server_id must not work
against a different one, even if the agent is bound to both).
"""

from unittest.mock import patch
from urllib.parse import urlparse, parse_qs

import pytest
from httpx import AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.core.security import generate_pkce_pair
from app.services.mcp_proxy_service import mcp_proxy_service


async def _register_client(
    client: AsyncClient, operator_token: str, application_type: str, redirect_uri: str
) -> dict:
    resp = await client.post(
        "/api/v1/oauth/register",
        headers={"Authorization": operator_token},
        json={
            "client_name": "Test MCP Client",
            "redirect_uris": [redirect_uri],
            "application_type": application_type,
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _authorize_and_get_code(
    client: AsyncClient,
    operator_token: str,
    *,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    agent_id: str,
    scope: str,
    resource: str | None,
    state: str = "xyz123",
) -> tuple[str, dict]:
    """Returns (code, parsed_query_params_from_redirect)."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "agent_id": agent_id,
        "scope": scope,
        "state": state,
    }
    if resource is not None:
        params["resource"] = resource

    resp = await client.get(
        "/api/v1/oauth/authorize",
        headers={"Authorization": operator_token},
        params=params,
    )
    assert resp.status_code == 302, resp.text
    location = resp.headers["location"]
    query = parse_qs(urlparse(location).query)
    assert "code" in query, f"no code in redirect: {location}"
    assert query["state"][0] == state
    assert "iss" in query
    return query["code"][0], query


@pytest.mark.asyncio
async def test_discovery_documents_and_jwks(client: AsyncClient):
    as_meta = await client.get("/.well-known/oauth-authorization-server")
    assert as_meta.status_code == 200, as_meta.text
    data = as_meta.json()
    assert data["authorization_endpoint"].endswith("/api/v1/oauth/authorize")
    assert data["token_endpoint"].endswith("/api/v1/oauth/token")
    assert data["registration_endpoint"].endswith("/api/v1/oauth/register")
    assert "S256" in data["code_challenge_methods_supported"]
    assert data["resource_indicators_supported"] is True

    prm = await client.get("/.well-known/oauth-protected-resource")
    assert prm.status_code == 200, prm.text
    prm_data = prm.json()
    assert prm_data["resource"].endswith("/api/v1/mcp")
    assert data["issuer"] in prm_data["authorization_servers"]

    jwks = await client.get("/.well-known/jwks.json")
    assert jwks.status_code == 200, jwks.text
    keys = jwks.json()["keys"]
    assert len(keys) == 1
    assert keys[0]["kty"] == "RSA"
    assert keys[0]["alg"] == "RS256"
    assert "n" in keys[0] and "e" in keys[0]


@pytest.mark.asyncio
async def test_register_client_web_requires_https_redirect(client: AsyncClient, operator_token: str):
    resp = await client.post(
        "/api/v1/oauth/register",
        headers={"Authorization": operator_token},
        json={
            "client_name": "Insecure Web Client",
            "redirect_uris": ["http://insecure.example.com/callback"],
            "application_type": "web",
        },
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"]["error"] == "invalid_client_metadata"


@pytest.mark.asyncio
async def test_register_client_native_allows_loopback_http_redirect(client: AsyncClient, operator_token: str):
    data = await _register_client(client, operator_token, "native", "http://127.0.0.1:54321/callback")
    assert data["client_id"].startswith("mcpc_")
    assert data["token_endpoint_auth_method"] == "none"
    assert data["application_type"] == "native"


@pytest.mark.asyncio
async def test_authorization_code_pkce_flow_mints_resource_bound_token_usable_against_mcp_proxy(
    client: AsyncClient, operator_token: str, test_agent: Agent,
):
    reg = await _register_client(client, operator_token, "native", "http://127.0.0.1:54321/callback")
    verifier, challenge = generate_pkce_pair()

    code, _ = await _authorize_and_get_code(
        client, operator_token,
        client_id=reg["client_id"],
        redirect_uri="http://127.0.0.1:54321/callback",
        code_challenge=challenge,
        agent_id=test_agent.id,
        scope="tool:execute",
        resource="srv-1",
    )

    token_resp = await client.post(
        "/api/v1/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://127.0.0.1:54321/callback",
            "client_id": reg["client_id"],
            "code_verifier": verifier,
            "resource": "srv-1",
        },
    )
    assert token_resp.status_code == 200, token_resp.text
    token_data = token_resp.json()
    assert token_data["scope"] == "tool:execute"
    agent_token = f"Bearer {token_data['access_token']}"

    # The token is real and resource-bound: it works through the MCP
    # proxy against the exact server it was authorized for.
    with patch(
        "app.services.mcp_proxy_service.check_permission", return_value=True
    ), patch.object(
        mcp_proxy_service, "_call_mcp_server", return_value=({"result": "ok"}, None)
    ):
        tool_resp = await client.post(
            "/api/v1/mcp/tools/search_web",
            headers={"Authorization": agent_token},
            json={"mcp_server_id": "srv-1", "arguments": {"q": "test"}},
        )
    assert tool_resp.status_code == 200, tool_resp.text

    # The code is single-use — redeeming it again must fail.
    replay_resp = await client.post(
        "/api/v1/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://127.0.0.1:54321/callback",
            "client_id": reg["client_id"],
            "code_verifier": verifier,
            "resource": "srv-1",
        },
    )
    assert replay_resp.status_code == 400
    assert replay_resp.json()["detail"]["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_resource_bound_token_rejected_against_a_different_mcp_server(
    client: AsyncClient, operator_token: str, test_agent: Agent, db_session: AsyncSession,
):
    """
    The agent is bound to BOTH srv-1 and srv-2 (SSRF-safe bindings), but
    a token minted with resource=srv-1 must still be refused against
    srv-2 — RFC 8707 Resource Indicators, composing with (not replacing)
    the existing mcp_bindings allowlist.
    """
    await db_session.execute(
        update(Agent).where(Agent.id == test_agent.id).values(
            mcp_bindings=[
                {"server_id": "srv-1", "server_url": "http://mock-mcp:8080", "tool_filter": ["search_web"]},
                {"server_id": "srv-2", "server_url": "http://mock-mcp-2:8080", "tool_filter": ["search_web"]},
            ]
        )
    )
    await db_session.commit()

    reg = await _register_client(client, operator_token, "native", "http://127.0.0.1:54322/callback")
    verifier, challenge = generate_pkce_pair()

    code, _ = await _authorize_and_get_code(
        client, operator_token,
        client_id=reg["client_id"],
        redirect_uri="http://127.0.0.1:54322/callback",
        code_challenge=challenge,
        agent_id=test_agent.id,
        scope="tool:execute",
        resource="srv-1",
    )
    token_resp = await client.post(
        "/api/v1/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://127.0.0.1:54322/callback",
            "client_id": reg["client_id"],
            "code_verifier": verifier,
            "resource": "srv-1",
        },
    )
    assert token_resp.status_code == 200, token_resp.text
    agent_token = f"Bearer {token_resp.json()['access_token']}"

    with patch("app.services.mcp_proxy_service.check_permission", return_value=True):
        resp = await client.post(
            "/api/v1/mcp/tools/search_web",
            headers={"Authorization": agent_token},
            json={"mcp_server_id": "srv-2", "arguments": {"q": "test"}},
        )
    assert resp.status_code == 403, resp.text
    assert "Resource Indicators" in resp.json()["detail"]["reason"]


@pytest.mark.asyncio
async def test_token_endpoint_rejects_wrong_pkce_verifier(
    client: AsyncClient, operator_token: str, test_agent: Agent,
):
    reg = await _register_client(client, operator_token, "native", "http://127.0.0.1:54323/callback")
    _verifier, challenge = generate_pkce_pair()
    wrong_verifier, _ = generate_pkce_pair()

    code, _ = await _authorize_and_get_code(
        client, operator_token,
        client_id=reg["client_id"],
        redirect_uri="http://127.0.0.1:54323/callback",
        code_challenge=challenge,
        agent_id=test_agent.id,
        scope="tool:execute",
        resource="srv-1",
    )
    resp = await client.post(
        "/api/v1/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://127.0.0.1:54323/callback",
            "client_id": reg["client_id"],
            "code_verifier": wrong_verifier,
            "resource": "srv-1",
        },
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_token_endpoint_rejects_mismatched_resource(
    client: AsyncClient, operator_token: str, test_agent: Agent, db_session: AsyncSession,
):
    await db_session.execute(
        update(Agent).where(Agent.id == test_agent.id).values(
            mcp_bindings=[
                {"server_id": "srv-1", "server_url": "http://mock-mcp:8080", "tool_filter": ["search_web"]},
                {"server_id": "srv-2", "server_url": "http://mock-mcp-2:8080", "tool_filter": ["search_web"]},
            ]
        )
    )
    await db_session.commit()

    reg = await _register_client(client, operator_token, "native", "http://127.0.0.1:54324/callback")
    verifier, challenge = generate_pkce_pair()

    code, _ = await _authorize_and_get_code(
        client, operator_token,
        client_id=reg["client_id"],
        redirect_uri="http://127.0.0.1:54324/callback",
        code_challenge=challenge,
        agent_id=test_agent.id,
        scope="tool:execute",
        resource="srv-1",
    )
    resp = await client.post(
        "/api/v1/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://127.0.0.1:54324/callback",
            "client_id": reg["client_id"],
            "code_verifier": verifier,
            "resource": "srv-2",  # not what /authorize authorized
        },
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["error"] == "invalid_target"
