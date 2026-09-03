import React, { useState } from 'react';
import { ShieldCheck, Hash, GitCommit, ArrowRight, CheckCircle2, AlertOctagon, Search, RefreshCw } from 'lucide-react';

export default function AuditLogTable({ logs, onRefresh }) {
  const [searchTerm, setSearchTerm] = useState('');

  const filteredLogs = logs.filter((log) =>
    log.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
    log.actor_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
    log.causal_trace_id?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    log.entry_hash?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
        <div>
          <h2 className="font-outfit" style={{ fontSize: '1.75rem', fontWeight: 700, color: '#fff' }}>
            Append-Only SHA256 Causal Hash Ledger
          </h2>
          <p style={{ color: 'var(--color-text-muted)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
            Tamper-evident sequential linking (`entry_hash` $\leftarrow$ `previous_hash`) across all operator and agent actions
          </p>
        </div>
        <button
          onClick={onRefresh}
          className="btn-secondary"
          style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
        >
          <RefreshCw size={16} color="#00f5ff" />
          <span>Refresh Ledger Feed</span>
        </button>
      </div>

      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        {/* Search Input */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem', background: 'rgba(6, 11, 25, 0.8)', padding: '0.6rem 1rem', borderRadius: '8px', border: '1px solid var(--color-border-glass)' }}>
          <Search size={18} color="#94a3b8" />
          <input
            type="text"
            placeholder="Search by Action, Actor ID, Causal Trace ID, or SHA256 Hash..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{ background: 'transparent', border: 'none', color: '#fff', width: '100%', outline: 'none', fontSize: '0.88rem' }}
          />
        </div>

        {/* Ledger Table */}
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--color-border-glass)', color: 'var(--color-text-muted)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                <th style={{ padding: '0.85rem 1rem' }}>Seq #</th>
                <th style={{ padding: '0.85rem 1rem' }}>Action & Causal Trace</th>
                <th style={{ padding: '0.85rem 1rem' }}>Actor</th>
                <th style={{ padding: '0.85rem 1rem' }}>Outcome</th>
                <th style={{ padding: '0.85rem 1rem' }}>SHA256 Hash Chain (`Previous $\rightarrow$ Current`)</th>
                <th style={{ padding: '0.85rem 1rem' }}>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {filteredLogs.map((log) => {
                const isSuccess = log.outcome === 'success';
                return (
                  <tr
                    key={log.id}
                    style={{
                      borderBottom: '1px solid rgba(255,255,255,0.04)',
                      transition: 'background 0.15s ease',
                    }}
                  >
                    <td style={{ padding: '1rem' }}>
                      <span className="font-mono" style={{ background: 'rgba(0, 245, 255, 0.12)', color: '#00f5ff', padding: '0.25rem 0.5rem', borderRadius: '6px', fontSize: '0.78rem', fontWeight: 600 }}>
                        #{log.sequence_number}
                      </span>
                    </td>

                    <td style={{ padding: '1rem' }}>
                      <div style={{ fontWeight: 600, color: '#fff', fontSize: '0.9rem' }}>{log.action}</div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', marginTop: '0.25rem' }}>
                        <GitCommit size={13} color="#00f5ff" />
                        <span className="font-mono" style={{ fontSize: '0.72rem', color: '#94a3b8' }}>
                          {log.causal_trace_id}
                        </span>
                      </div>
                    </td>

                    <td style={{ padding: '1rem' }}>
                      <div style={{ fontSize: '0.85rem', color: '#e2e8f0', fontWeight: 500 }}>{log.actor_id}</div>
                      <span style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase' }}>{log.actor_type}</span>
                    </td>

                    <td style={{ padding: '1rem' }}>
                      <span
                        className="badge"
                        style={{
                          background: isSuccess ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)',
                          color: isSuccess ? '#34d399' : '#fb7185',
                          border: `1px solid ${isSuccess ? 'rgba(16, 185, 129, 0.35)' : 'rgba(244, 63, 94, 0.35)'}`,
                        }}
                      >
                        {isSuccess ? <CheckCircle2 size={12} /> : <AlertOctagon size={12} />}
                        {log.outcome}
                      </span>
                    </td>

                    <td style={{ padding: '1rem' }}>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem', maxWidth: '380px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                          <span style={{ fontSize: '0.68rem', color: '#64748b', width: '35px' }}>Prev:</span>
                          <code className="font-mono" style={{ fontSize: '0.72rem', color: '#94a3b8', background: 'rgba(0,0,0,0.3)', padding: '0.15rem 0.4rem', borderRadius: '4px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block', flex: 1 }}>
                            {log.previous_hash || 'GENESIS_ZERO_HASH'}
                          </code>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                          <span style={{ fontSize: '0.68rem', color: '#00f5ff', fontWeight: 600, width: '35px' }}>Curr:</span>
                          <code className="font-mono" style={{ fontSize: '0.72rem', color: '#00f5ff', background: 'rgba(0, 245, 255, 0.08)', border: '1px solid rgba(0, 245, 255, 0.2)', padding: '0.15rem 0.4rem', borderRadius: '4px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block', flex: 1 }}>
                            {log.entry_hash}
                          </code>
                        </div>
                      </div>
                    </td>

                    <td style={{ padding: '1rem', fontSize: '0.78rem', color: 'var(--color-text-muted)', whiteSpace: 'nowrap' }}>
                      {new Date(log.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
