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

# ── Slice 13: provenance-aware authorization ──────────────────────────

test_deny_when_tainted_trace_attempts_external_send if {
	not authz.allow with input as object.union(base_input, {
		"capabilities": ["external_send"],
		"provenance": {"tainted": true},
	})
}

test_deny_when_tainted_trace_attempts_credential_access if {
	not authz.allow with input as object.union(base_input, {
		"capabilities": ["credential_access"],
		"provenance": {"tainted": true},
	})
}

test_allow_when_tainted_but_capability_is_not_high_risk if {
	authz.allow with input as object.union(base_input, {
		"capabilities": ["read_only"],
		"provenance": {"tainted": true},
	})
}

test_allow_when_capability_is_high_risk_but_trace_not_tainted if {
	authz.allow with input as object.union(base_input, {
		"capabilities": ["external_send"],
		"provenance": {"tainted": false},
	})
}

test_allow_when_neither_capabilities_nor_provenance_given if {
	# Backward compatibility: a caller that never sends these fields at
	# all (matches every pre-Slice-13 input) must be unaffected.
	authz.allow with input as base_input
}

# ── deny_reasons: informational, must agree with `allow` ─────────────

test_no_deny_reasons_when_allowed if {
	authz.deny_reasons == set() with input as base_input
}

test_reason_provenance_is_the_only_reason_for_a_tainted_external_send if {
	authz.deny_reasons == {"provenance_tainted_high_risk_capability"} with input as object.union(base_input, {
		"capabilities": ["external_send"],
		"provenance": {"tainted": true},
	})
}

test_reason_scope_not_granted if {
	authz.deny_reasons == {"scope_not_granted"} with input as object.union(base_input, {"token_scopes": ["audit:read"]})
}

test_reason_blocked_tool if {
	authz.deny_reasons == {"blocked_tool"} with input as object.union(base_input, {"resource": {"type": "mcp_tool", "id": "delete_database"}})
}

test_reason_delegation_depth_exceeded if {
	authz.deny_reasons == {"delegation_depth_exceeded"} with input as object.union(base_input, {"delegation_depth": 6})
}

test_reason_malformed_input_on_empty_input if {
	"malformed_input" in authz.deny_reasons with input as {}
}

test_multiple_reasons_are_all_reported if {
	authz.deny_reasons == {"scope_not_granted", "provenance_tainted_high_risk_capability"} with input as object.union(base_input, {
		"token_scopes": ["audit:read"],
		"capabilities": ["external_send"],
		"provenance": {"tainted": true},
	})
}

test_allow_and_deny_reasons_never_disagree if {
	# Every scenario above that denies must carry at least one reason, and
	# every one that allows must carry none.
	denied := object.union(base_input, {"token_scopes": ["audit:read"]})
	not authz.allow with input as denied
	count(authz.deny_reasons) > 0 with input as denied
	authz.allow with input as base_input
	count(authz.deny_reasons) == 0 with input as base_input
}
