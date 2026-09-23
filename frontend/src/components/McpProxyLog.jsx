import React from 'react';
import { ShieldX, ShieldCheck, Hash, Clock, RefreshCw } from 'lucide-react';

// One label per kind of block (McpSession.policy_decision — see
// mcp_proxy_service._block). Not every block is an OPA denial: a tool_filter
// block never reaches OPA, and a provenance denial is a different failure
// from a missing scope. Rows written before this distinction existed carry
// the generic "blocked", and any unknown value falls back to the same.
const BLOCK_LABELS = {
  policy_denied: 'OPA POLICY DENIED',
  provenance_denied: 'PROVENANCE DENIED',
  policy_unavailable: 'POLICY ENGINE UNAVAILABLE',
  tool_filter_denied: 'TOOL FILTER BLOCKED',
  binding_denied: 'NO MCP BINDING',
  resource_denied: 'RESOURCE MISMATCH',
  task_scope_denied: 'TASK SCOPE DENIED',
};

const blockLabel = (decision) => BLOCK_LABELS[decision] || 'BLOCKED';

export default function McpProxyLog({ sessions, onRefresh }) {
  return (
    <div>
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-3 mb-8">
        <div>
          <h2 className="font-outfit text-2xl md:text-3xl font-bold text-ink-900">
            Pre-Execution MCP Proxy ReBAC Intercept Feeds
          </h2>
          <p className="text-text-muted text-sm mt-1">
            All tool execution attempts (`/api/v1/mcp/tools/*`) are evaluated by Open Policy Agent (`OPA`) *before* forwarding HTTP requests
          </p>
        </div>
        <button onClick={onRefresh} className="btn-secondary flex items-center gap-2 self-start">
          <RefreshCw size={16} className="text-brand-red" />
          <span>Refresh Intercept Logs</span>
        </button>
      </div>

      <div className="flex flex-col gap-4">
        {sessions.map((sess) => {
          const isAllowed = sess.policy_decision === 'allowed';
          return (
            <div
              key={sess.id}
              className={`glass-panel p-6 border-l-4 flex items-center justify-between flex-wrap gap-6 ${
                isAllowed ? 'border-l-emerald-500' : 'border-l-rose-500'
              }`}
            >
              <div className="flex items-start gap-4 min-w-[320px]">
                <div
                  className={`p-2.5 rounded-xl flex items-center justify-center ${
                    isAllowed
                      ? 'bg-emerald-500/15 border border-emerald-500'
                      : 'bg-rose-500/15 border border-rose-500'
                  }`}
                >
                  {isAllowed ? <ShieldCheck size={24} className="text-emerald-600" /> : <ShieldX size={24} className="text-rose-600" />}
                </div>
                <div>
                  <div className="flex items-center gap-2.5 mb-1 flex-wrap">
                    <h3 className="font-outfit text-lg font-semibold text-ink-900">
                      Tool Call: <code className="font-mono text-brand-red">{sess.tool_name}</code>
                    </h3>
                    <span
                      className="badge"
                      style={{
                        background: isAllowed ? '#ecfdf5' : '#fff1f2',
                        color: isAllowed ? '#047857' : '#be123c',
                        border: `1px solid ${isAllowed ? '#a7f3d0' : '#fecdd3'}`,
                      }}
                    >
                      {isAllowed ? 'OPA REBAC ALLOWED' : `${blockLabel(sess.policy_decision)} (HTTP 403)`}
                    </span>
                  </div>

                  <div className="text-sm text-slate-600 mb-2">
                    Agent: <span className="font-mono text-slate-700">{sess.agent_id}</span> • Server: <span className="font-mono text-text-muted">{sess.mcp_server_id}</span>
                  </div>

                  {!isAllowed && (
                    <div className="bg-rose-50 border border-rose-300 px-3 py-2 rounded-md text-sm text-rose-700 mt-2">
                      <strong>Fail-Closed Intercept:</strong> {sess.blocking_reason}
                    </div>
                  )}
                </div>
              </div>

              {/* Hash Metadata & Duration */}
              <div className="flex flex-col gap-1.5 bg-surface-100 px-4 py-3.5 rounded-lg border border-slate-200 min-w-[300px]">
                <div className="flex items-center gap-1.5">
                  <Hash size={14} className="text-brand-red" />
                  <span className="text-xs font-semibold text-text-muted uppercase">Privacy-Preserving SHA256 Payload Hash</span>
                </div>
                <code className="font-mono text-xs text-brand-red break-all">
                  {sess.args_hash || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
                </code>
                <div className="flex justify-between items-center text-xs text-text-muted mt-1 border-t border-slate-200 pt-1.5">
                  <span>Causal Trace: <code className="font-mono text-slate-600">{sess.causal_trace_id}</code></span>
                  <span className="flex items-center gap-1">
                    <Clock size={12} /> {sess.duration_ms} ms
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
