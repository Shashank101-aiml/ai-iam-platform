package aiiam.authz

# Pre-execution ReBAC policy for the AI-IAM platform. Queried by
# app/core/permissions.py::check_permission on every tool-call
# authorization decision, before the call reaches an external MCP
# server — see docs/threat-model.md and services/mcp_proxy_service.py.
#
# Input shape (see check_permission's opa_input construction):
#   {
#     "agent_id": "...", "org_id": "...", "action": "tool:execute",
#     "resource": {"type": "mcp_tool", "id": "search_web"},
#     "token_scopes": ["tool:execute", ...], "delegation_depth": 0
#   }

# Fail closed: anything that doesn't affirmatively satisfy `allow`
# below — including a malformed or empty input document — is denied.
# check_permission also fail-closes independently on any OPA timeout
# or connection error, so this default only matters when OPA itself
# is reachable and answers.
default allow := false

# Hard ceiling matching settings.MAX_DELEGATION_DEPTH. Duplicated here
# deliberately, not read from input: OPA is meant to be a second,
# independent enforcement point, not a rubber stamp for whatever the
# application layer already decided. If this constant and the app
# setting drift apart, that's a real signal worth catching, not
# something to paper over by trusting the caller's own number.
max_delegation_depth := 5

# Tools blocked outright regardless of scope or depth — the case a
# scope check alone can't express (an agent legitimately holding
# tool:execute should still never be able to drop a table through it).
# This is a placeholder for a real per-org allow/deny list, which
# should eventually be `data` pushed via an OPA bundle or the
# management API rather than hardcoded in the policy module — but
# genuine deny-by-policy needs to exist before that data source does.
blocked_tools := {
	"delete_database",
	"drop_table",
	"exfiltrate_data",
	"rm_rf",
}

allow if {
	well_formed_input
	input.action in input.token_scopes
	input.delegation_depth <= max_delegation_depth
	not is_blocked_tool_call
}

# Baseline input sanity — not a real cross-org check (nothing in this
# input shape names a second org to match against), but refusing to
# allow a request that doesn't even identify its agent/org is cheap
# insurance against a caller bug upstream.
well_formed_input if {
	input.org_id != ""
	input.agent_id != ""
}

is_blocked_tool_call if {
	input.action == "tool:execute"
	input.resource.type == "mcp_tool"
	input.resource.id in blocked_tools
}
