import React, { useState } from 'react';
import { GitCommit, CheckCircle2, AlertOctagon, Search, RefreshCw } from 'lucide-react';

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
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-3 mb-8">
        <div>
          <h2 className="font-outfit text-2xl md:text-3xl font-bold text-ink-900">
            Append-Only SHA256 Causal Hash Ledger
          </h2>
          <p className="text-text-muted text-sm mt-1">
            Tamper-evident sequential linking (`entry_hash` ← `previous_hash`) across all operator and agent actions
          </p>
        </div>
        <button onClick={onRefresh} className="btn-secondary flex items-center gap-2 self-start">
          <RefreshCw size={16} className="text-brand-red" />
          <span>Refresh Ledger Feed</span>
        </button>
      </div>

      <div className="glass-panel p-6">
        {/* Search Input */}
        <div className="flex items-center gap-3 mb-6 bg-surface-100 px-4 py-2.5 rounded-lg border border-border-glass">
          <Search size={18} className="text-text-muted" />
          <input
            type="text"
            placeholder="Search by Action, Actor ID, Causal Trace ID, or SHA256 Hash..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="bg-transparent border-none text-ink-900 w-full outline-none text-sm"
          />
        </div>

        {/* Ledger Table */}
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left">
            <thead>
              <tr className="border-b border-border-glass text-text-muted text-xs uppercase tracking-wide">
                <th className="px-4 py-3.5">Seq #</th>
                <th className="px-4 py-3.5">Action & Causal Trace</th>
                <th className="px-4 py-3.5">Actor</th>
                <th className="px-4 py-3.5">Outcome</th>
                <th className="px-4 py-3.5">SHA256 Hash Chain (`Previous → Current`)</th>
                <th className="px-4 py-3.5">Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {filteredLogs.map((log) => {
                const isSuccess = log.outcome === 'success';
                return (
                  <tr key={log.id} className="border-b border-white/5">
                    <td className="p-4">
                      <span className="font-mono bg-brand-red/8 text-brand-red px-2 py-1 rounded-md text-[0.78rem] font-semibold">
                        #{log.sequence_number}
                      </span>
                    </td>

                    <td className="p-4">
                      <div className="font-semibold text-ink-900 text-sm">{log.action}</div>
                      <div className="flex items-center gap-1.5 mt-1">
                        <GitCommit size={13} className="text-brand-red" />
                        <span className="font-mono text-xs text-text-muted">
                          {log.causal_trace_id}
                        </span>
                      </div>
                    </td>

                    <td className="p-4">
                      <div className="text-sm text-slate-700 font-medium">{log.actor_id}</div>
                      <span className="text-xs text-slate-400 uppercase">{log.actor_type}</span>
                    </td>

                    <td className="p-4">
                      <span
                        className="badge"
                        style={{
                          background: isSuccess ? '#ecfdf5' : '#fff1f2',
                          color: isSuccess ? '#047857' : '#be123c',
                          border: `1px solid ${isSuccess ? '#a7f3d0' : '#fecdd3'}`,
                        }}
                      >
                        {isSuccess ? <CheckCircle2 size={12} /> : <AlertOctagon size={12} />}
                        {log.outcome}
                      </span>
                    </td>

                    <td className="p-4">
                      <div className="flex flex-col gap-1 max-w-[380px]">
                        <div className="flex items-center gap-1.5">
                          <span className="text-[0.68rem] text-slate-400 w-9">Prev:</span>
                          <code className="font-mono text-xs text-text-muted bg-slate-100 px-1.5 py-0.5 rounded truncate flex-1">
                            {log.previous_hash || 'GENESIS_ZERO_HASH'}
                          </code>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <span className="text-[0.68rem] text-brand-red font-semibold w-9">Curr:</span>
                          <code className="font-mono text-xs text-brand-red bg-brand-red/8 border border-brand-red/20 px-1.5 py-0.5 rounded truncate flex-1">
                            {log.entry_hash}
                          </code>
                        </div>
                      </div>
                    </td>

                    <td className="p-4 text-[0.78rem] text-text-muted whitespace-nowrap">
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
