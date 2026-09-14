"""
Slice 12 tests: task-scoped tokens (RFC 9396 authorization_details).

Closes the "ambient authority" gap — a session-scoped bearer token
today authorizes ANY tool call its scopes cover for its whole 15-minute
lifetime, not just the one it was minted for. Covers: minting a token
scoped to one tool and getting a DISTINCT denial (not a generic policy
403) when it's replayed against a different tool; a correctly-scoped
token still working against the tool it WAS minted for; session-scoped
(no intent) behavior staying unchanged for ordinary scopes; and
credential:rotate being refused at mint time without task-scoping.
"""

from unittest.mock import patch

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.services.mcp_proxy_service import mcp_proxy_service


async def _issue_and_exchange(
    client: AsyncClient, operator_token: str, agent: Agent, scopes: list[str], intent: dict | None = None
) -> dict:
    issue_resp = await client.post(
        f"/api/v1/agents/{agent.id}/keys",
        headers={"Authorization": operator_token},
        json={"scopes": scopes, "ttl_days": 30},
    )
    assert issue_resp.status_code == 201, issue_resp.text
    key_data = issue_resp.json()
    body = {"grant_type": "api_key", "credential": f"{key_data['key_id']}:{key_data['plaintext_key']}"}
    if intent is not None:
        body["intent"] = intent
    exchange_resp = await client.post("/api/v1/token/exchange", json=body)
    return exchange_resp


@pytest_asyncio.fixture(autouse=True)
async def _widen_test_agent_tool_filter(db_session: AsyncSession, test_agent: Agent):
    """test_agent's default binding only allow-lists 'search_web' — these tests need at least two tools on the same server."""
    await db_session.execute(
        update(Agent).where(Agent.id == test_agent.id).values(
            mcp_bindings=[
                {"server_id": "srv-1", "server_url": "http://mock-mcp:8080", "tool_filter": ["search_web", "read_file"]},
            ]
        )
    )
    await db_session.commit()


@pytest.mark.asyncio
async def test_task_scoped_token_rejected_against_a_different_tool(
    client: AsyncClient, operator_token: str, test_agent: Agent,
):
    exchange_resp = await _issue_and_exchange(
        client, operator_token, test_agent, ["tool:execute"],
        intent={"mcp_server_id": "srv-1", "tool_name": "search_web"},
    )
    assert exchange_resp.status_code == 200, exchange_resp.text
    token_data = exchange_resp.json()
    assert token_data["authorization_details"] == [
        {"type": "mcp_tool_call", "mcp_server_id": "srv-1", "tool_name": "search_web"}
    ]
    agent_token = f"Bearer {token_data['access_token']}"

    # Same agent, same server, a DIFFERENT (but scope-valid, tool_filter-valid) tool.
    with patch("app.services.mcp_proxy_service.check_permission", return_value=True):
        resp = await client.post(
            "/api/v1/mcp/tools/read_file",
            headers={"Authorization": agent_token},
            json={"mcp_server_id": "srv-1", "arguments": {}},
        )
    assert resp.status_code == 403, resp.text
    detail = resp.json()["detail"]
    assert detail["error"] == "token_not_authorized_for_action"


@pytest.mark.asyncio
async def test_task_scoped_token_works_against_the_tool_it_was_minted_for(
    client: AsyncClient, operator_token: str, test_agent: Agent,
):
    exchange_resp = await _issue_and_exchange(
        client, operator_token, test_agent, ["tool:execute"],
        intent={"mcp_server_id": "srv-1", "tool_name": "search_web"},
    )
    assert exchange_resp.status_code == 200, exchange_resp.text
    agent_token = f"Bearer {exchange_resp.json()['access_token']}"

    with patch(
        "app.services.mcp_proxy_service.check_permission", return_value=True
    ), patch.object(
        mcp_proxy_service, "_call_mcp_server", return_value=({"result": "ok"}, None)
    ):
        resp = await client.post(
            "/api/v1/mcp/tools/search_web",
            headers={"Authorization": agent_token},
            json={"mcp_server_id": "srv-1", "arguments": {}},
        )
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_session_scoped_token_unaffected_when_no_intent_given(
    client: AsyncClient, operator_token: str, test_agent: Agent,
):
    """Backward compatibility: omitting intent entirely still works exactly as before Slice 12, for ordinary scopes."""
    exchange_resp = await _issue_and_exchange(client, operator_token, test_agent, ["tool:execute"])
    assert exchange_resp.status_code == 200, exchange_resp.text
    assert exchange_resp.json()["authorization_details"] is None
    agent_token = f"Bearer {exchange_resp.json()['access_token']}"

    with patch(
        "app.services.mcp_proxy_service.check_permission", return_value=True
    ), patch.object(
        mcp_proxy_service, "_call_mcp_server", return_value=({"result": "ok"}, None)
    ):
        for tool in ("search_web", "read_file"):
            resp = await client.post(
                f"/api/v1/mcp/tools/{tool}",
                headers={"Authorization": agent_token},
                json={"mcp_server_id": "srv-1", "arguments": {}},
            )
            assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_invalid_intent_rejected_at_mint_time(
    client: AsyncClient, operator_token: str, test_agent: Agent,
):
    """An intent naming a server/tool the agent could never actually reach is refused before a token is even minted."""
    resp = await _issue_and_exchange(
        client, operator_token, test_agent, ["tool:execute"],
        intent={"mcp_server_id": "srv-1", "tool_name": "drop_table"},  # not in tool_filter
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "invalid_intent"


@pytest.mark.asyncio
async def test_dangerous_scope_requires_task_scoping(
    client: AsyncClient, operator_token: str, db_session: AsyncSession, test_agent: Agent,
):
    # credential:rotate isn't in test_agent's default allowed_scopes — add it.
    await db_session.execute(
        update(Agent).where(Agent.id == test_agent.id).values(
            allowed_scopes=["tool:execute", "credential:rotate"]
        )
    )
    await db_session.commit()

    without_intent = await _issue_and_exchange(client, operator_token, test_agent, ["credential:rotate"])
    assert without_intent.status_code == 422
    assert without_intent.json()["detail"]["error"] == "task_scoping_required"

    with_intent = await _issue_and_exchange(
        client, operator_token, test_agent, ["credential:rotate"],
        intent={"mcp_server_id": "srv-1", "tool_name": "search_web"},
    )
    assert with_intent.status_code == 200, with_intent.text
    assert with_intent.json()["authorization_details"] is not None
