import React from 'react';
import { ShieldX, ShieldCheck, Hash, Clock, RefreshCw } from 'lucide-react';

export default function McpProxyLog({ sessions, onRefresh }) {
  return (
    <div>
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-3 mb-8">
        <div>
          <h2 className="font-outfit text-2xl md:text-3xl font-bold text-white">
            Pre-Execution MCP Proxy ReBAC Intercept Feeds
          </h2>
          <p className="text-text-muted text-sm mt-1">
            All tool execution attempts (`/api/v1/mcp/tools/*`) are evaluated by Open Policy Agent (`OPA`) *before* forwarding HTTP requests
          </p>
        </div>
        <button onClick={onRefresh} className="btn-secondary flex items-center gap-2 self-start">
          <RefreshCw size={16} className="text-cyan-glow" />
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
                  {isAllowed ? <ShieldCheck size={24} className="text-emerald-400" /> : <ShieldX size={24} className="text-rose-400" />}
                </div>
                <div>
                  <div className="flex items-center gap-2.5 mb-1 flex-wrap">
                    <h3 className="font-outfit text-lg font-semibold text-white">
                      Tool Call: <code className="font-mono text-cyan-glow">{sess.tool_name}</code>
                    </h3>
                    <span
                      className="badge"
                      style={{
                        background: isAllowed ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)',
                        color: isAllowed ? '#34d399' : '#fb7185',
                        border: `1px solid ${isAllowed ? 'rgba(16, 185, 129, 0.35)' : 'rgba(244, 63, 94, 0.35)'}`,
                      }}
                    >
                      {isAllowed ? 'OPA REBAC ALLOWED' : 'OPA REBAC BLOCKED (HTTP 403)'}
                    </span>
                  </div>

                  <div className="text-sm text-slate-300 mb-2">
                    Agent: <span className="font-mono text-slate-200">{sess.agent_id}</span> • Server: <span className="font-mono text-text-muted">{sess.mcp_server_id}</span>
                  </div>

                  {!isAllowed && (
                    <div className="bg-rose-500/10 border border-rose-500/30 px-3 py-2 rounded-md text-sm text-rose-300 mt-2">
                      <strong>Fail-Closed Intercept:</strong> {sess.blocking_reason}
                    </div>
                  )}
                </div>
              </div>

              {/* Hash Metadata & Duration */}
              <div className="flex flex-col gap-1.5 bg-bg-deep/70 px-4 py-3.5 rounded-lg border border-white/5 min-w-[300px]">
                <div className="flex items-center gap-1.5">
                  <Hash size={14} className="text-cyan-glow" />
                  <span className="text-xs font-semibold text-text-muted uppercase">Privacy-Preserving SHA256 Payload Hash</span>
                </div>
                <code className="font-mono text-xs text-cyan-glow break-all">
                  {sess.args_hash || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
                </code>
                <div className="flex justify-between items-center text-xs text-text-muted mt-1 border-t border-white/5 pt-1.5">
                  <span>Causal Trace: <code className="font-mono text-slate-300">{sess.causal_trace_id}</code></span>
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
