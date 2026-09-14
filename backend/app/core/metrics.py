"""
Domain-specific Prometheus metrics (Slice 14).

prometheus-fastapi-instrumentator (wired in main.py's create_app) already
gives request-count/latency histograms for free, labeled by route and
status code — that's generic HTTP instrumentation. Everything here is a
domain counter/histogram the generic layer has no way to infer, because
it doesn't know WHY a call was denied, how deep delegation chains
actually get in practice, how often credentials actually rotate, or how
long a full audit-chain replay takes. Each metric is updated at the one
call site that has the information to fill in its labels correctly, not
recomputed from logs after the fact.
"""

from prometheus_client import Counter, Histogram

# Labeled by the SAME policy_decision values already recorded on
# McpSession rows ("blocked", "task_scope_denied", ...) — see
# mcp_proxy_service._block — so this metric and that column always agree
# on taxonomy instead of drifting into two different vocabularies.
MCP_TOOL_DENIALS_TOTAL = Counter(
    "aiiam_mcp_tool_denials_total",
    "MCP tool calls blocked before execution, by policy_decision reason.",
    ["policy_decision"],
)

# The resulting depth of every delegation grant AT ISSUANCE — not a
# snapshot of "current depth in the DB" (which cascading revocation
# would distort over time), but what depth_service.delegate() actually
# approved at the moment it approved it.
DELEGATION_DEPTH = Histogram(
    "aiiam_delegation_depth",
    "Resulting depth of a delegation grant at the moment it was issued.",
    buckets=(0, 1, 2, 3, 4, 5, 6, 7, 8),
)

CREDENTIAL_ROTATIONS_TOTAL = Counter(
    "aiiam_credential_rotations_total",
    "API key rotations actually performed by the background rotator worker.",
)

# Observed around the ENTIRE audit_repo.verify_chain() call, so this
# covers both the periodic worker (worker/audit_verifier.py) and the
# on-demand GET /audit/verify endpoint from the same instrumentation
# point, rather than needing two separate call sites kept in sync.
AUDIT_CHAIN_VERIFY_DURATION_SECONDS = Histogram(
    "aiiam_audit_chain_verify_duration_seconds",
    "Wall-clock time to replay and verify one organization's audit hash chain.",
)
