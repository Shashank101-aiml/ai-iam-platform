import React, { useState } from 'react';
import { Terminal, ShieldX, ShieldCheck, Hash, Clock, CheckCircle2, AlertOctagon, RefreshCw } from 'lucide-react';

export default function McpProxyLog({ sessions, onRefresh }) {
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
        <div>
          <h2 className="font-outfit" style={{ fontSize: '1.75rem', fontWeight: 700, color: '#fff' }}>
            Pre-Execution MCP Proxy ReBAC Intercept Feeds
          </h2>
          <p style={{ color: 'var(--color-text-muted)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
            All tool execution attempts (`/api/v1/mcp/tools/*`) are evaluated by Open Policy Agent (`OPA`) *before* forwarding HTTP requests
          </p>
        </div>
        <button
          onClick={onRefresh}
          className="btn-secondary"
          style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
        >
          <RefreshCw size={16} color="#00f5ff" />
          <span>Refresh Intercept Logs</span>
        </button>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        {sessions.map((sess) => {
          const isAllowed = sess.policy_decision === 'allowed';
          return (
            <div
              key={sess.id}
              className="glass-panel"
              style={{
                padding: '1.5rem',
                borderLeft: isAllowed ? '4px solid #10b981' : '4px solid #f43f5e',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '1.5rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem', minWidth: '320px' }}>
                <div
                  style={{
                    padding: '0.65rem',
                    borderRadius: '12px',
                    background: isAllowed ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)',
                    border: `1px solid ${isAllowed ? '#10b981' : '#f43f5e'}`,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  {isAllowed ? <ShieldCheck size={24} color="#34d399" /> : <ShieldX size={24} color="#fb7185" />}
                </div>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.25rem' }}>
                    <h3 className="font-outfit" style={{ fontSize: '1.15rem', fontWeight: 600, color: '#fff' }}>
                      Tool Call: <code className="font-mono" style={{ color: '#00f5ff' }}>{sess.tool_name}</code>
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

                  <div style={{ fontSize: '0.82rem', color: '#cbd5e1', marginBottom: '0.5rem' }}>
                    Agent: <span className="font-mono" style={{ color: '#e2e8f0' }}>{sess.agent_id}</span> • Server: <span className="font-mono" style={{ color: '#94a3b8' }}>{sess.mcp_server_id}</span>
                  </div>

                  {!isAllowed && (
                    <div style={{ background: 'rgba(244, 63, 94, 0.1)', border: '1px solid rgba(244, 63, 94, 0.3)', padding: '0.5rem 0.75rem', borderRadius: '6px', fontSize: '0.78rem', color: '#fca5a5', marginTop: '0.5rem' }}>
                      <strong>Fail-Closed Intercept:</strong> {sess.blocking_reason}
                    </div>
                  )}
                </div>
              </div>

              {/* Hash Metadata & Duration */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', background: 'rgba(6, 11, 25, 0.7)', padding: '0.85rem 1rem', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)', minWidth: '340px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <Hash size={14} color="#00f5ff" />
                  <span style={{ fontSize: '0.72rem', fontWeight: 600, color: '#94a3b8', textTransform: 'uppercase' }}>Privacy-Preserving SHA256 Payload Hash</span>
                </div>
                <code className="font-mono" style={{ fontSize: '0.72rem', color: '#00f5ff', wordBreak: 'break-all' }}>
                  {sess.args_hash || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
                </code>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.72rem', color: 'var(--color-text-muted)', marginTop: '0.3rem', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '0.4rem' }}>
                  <span>Causal Trace: <code className="font-mono" style={{ color: '#cbd5e1' }}>{sess.causal_trace_id}</code></span>
                  <span style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
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
