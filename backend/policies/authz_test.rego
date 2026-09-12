package aiiam.authz_test

import data.aiiam.authz

base_input := {
	"agent_id": "agent-1",
	"org_id": "org-1",
	"action": "tool:execute",
	"resource": {"type": "mcp_tool", "id": "search_web"},
	"token_scopes": ["tool:execute"],
	"delegation_depth": 0,
}

test_allow_when_scope_present_and_depth_ok if {
	authz.allow with input as base_input
}

test_deny_by_default_on_empty_input if {
	not authz.allow with input as {}
}

test_deny_when_action_scope_missing if {
	not authz.allow with input as object.union(base_input, {"token_scopes": ["audit:read"]})
}

test_deny_when_depth_exceeds_ceiling if {
	not authz.allow with input as object.union(base_input, {"delegation_depth": 6})
}

test_allow_when_depth_at_ceiling if {
	authz.allow with input as object.union(base_input, {"delegation_depth": 5})
}

test_deny_when_tool_is_blocked_even_with_matching_scope if {
	not authz.allow with input as object.union(base_input, {"resource": {"type": "mcp_tool", "id": "delete_database"}})
}

test_deny_when_org_id_missing if {
	not authz.allow with input as object.union(base_input, {"org_id": ""})
}

test_deny_when_agent_id_missing if {
	not authz.allow with input as object.union(base_input, {"agent_id": ""})
}

test_allow_for_non_tool_action_ignores_blocked_tools_set if {
	authz.allow with input as object.union(base_input, {
		"action": "audit:read",
		"resource": {"type": "audit_log", "id": "log-1"},
		"token_scopes": ["audit:read"],
	})
}

test_deny_when_resource_type_is_not_mcp_tool_but_action_still_matches_blocked_name if {
	# A resource.id that happens to collide with a blocked tool name is
	# only relevant for actual tool:execute calls against mcp_tool
	# resources — this proves is_blocked_tool_call doesn't over-match.
	authz.allow with input as object.union(base_input, {
		"action": "audit:read",
		"resource": {"type": "audit_log", "id": "delete_database"},
		"token_scopes": ["audit:read"],
	})
}
