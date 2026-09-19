import React from 'react';
import { GitBranch, Shield, Lock } from 'lucide-react';

export default function DelegationChainViewer({ agents }) {
  const supervisor = agents.find((a) => !a.parent_agent_id) || agents[0];
  const children = agents.filter((a) => a.parent_agent_id === supervisor?.id) || [];

  return (
    <div>
      <div className="mb-8">
        <h2 className="font-outfit text-2xl md:text-3xl font-bold text-white">
          Multi-Hop Delegation & ReBAC Trust Tree
        </h2>
        <p className="text-text-muted text-sm mt-1">
          Enforces Mathematical Scope Attenuation (`Child Scopes ⊆ Parent Scopes`) and `MAX_DELEGATION_DEPTH` Ceilings
        </p>
      </div>

      <div className="glass-panel p-8 mb-8">
        <div className="flex items-center gap-3 mb-6 border-b border-border-glass pb-4">
          <GitBranch size={22} className="text-cyan-glow" />
          <h3 className="font-outfit text-xl font-semibold text-white">
            Live Attested Delegation Chain Visualization
          </h3>
        </div>

        {/* Root Node: Supervisor */}
        {supervisor && (
          <div className="relative rounded-xl p-5 max-w-[520px]" style={{ background: 'rgba(30, 58, 138, 0.4)', border: '1px solid #3b82f6' }}>
            <div className="flex justify-between items-center mb-3">
              <div className="flex items-center gap-2">
                <span className="badge badge-cyan">Root Tier 0</span>
                <span className="font-bold text-white text-[1.05rem]">{supervisor.name}</span>
              </div>
              <span className="font-mono text-xs text-blue-400">
                Depth: 0 / {supervisor.max_delegation_depth}
              </span>
            </div>
            <div className="text-sm text-slate-300 mb-3">
              SPIFFE Workload SVID: <code className="font-mono text-cyan-glow">{supervisor.spiffe_id}</code>
            </div>
            <div>
              <span className="text-xs text-text-muted uppercase font-semibold">Active Scopes:</span>
              <div className="flex flex-wrap gap-1.5 mt-1.5">
                {supervisor.allowed_scopes?.map((s, i) => (
                  <span key={i} className="font-mono text-xs bg-blue-500/20 text-blue-300 px-2 py-0.5 rounded">
                    {s}
                  </span>
                ))}
              </div>
            </div>

            {/* Connecting Arrow */}
            <div className="absolute -bottom-7 left-10 w-0.5 h-7 bg-border-accent" />
          </div>
        )}

        {/* Child Tier */}
        <div className="flex flex-col gap-6 mt-7 pl-10 border-l-2 border-dashed border-border-accent">
          {children.map((child) => (
            <div
              key={child.id}
              className="relative rounded-xl p-5 max-w-[480px] border border-border-glass"
              style={{ background: 'rgba(16, 26, 56, 0.8)' }}
            >
              <div className="absolute top-6 -left-[42px] w-10 h-0.5 bg-border-accent" />
              <div className="flex justify-between items-center mb-3">
                <div className="flex items-center gap-2">
                  <span className="badge" style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#34d399', border: '1px solid #10b981' }}>Tier 1 Delegatee</span>
                  <span className="font-bold text-white text-[0.98rem]">{child.name}</span>
                </div>
                <span className="font-mono text-xs text-text-muted">
                  Depth: 1 / {child.max_delegation_depth}
                </span>
              </div>
              <div className="text-sm text-slate-300 mb-3">
                Identifier: <code className="font-mono text-cyan-glow">{child.spiffe_id || 'Not assigned'}</code>
              </div>
              <div>
                <span className="text-xs text-text-muted uppercase font-semibold">Attenuated Subset Scopes:</span>
                <div className="flex flex-wrap gap-1.5 mt-1.5">
                  {child.allowed_scopes?.map((s, i) => (
                    <span key={i} className="font-mono text-xs bg-cyan-glow/10 text-cyan-glow px-2 py-0.5 rounded">
                      {s}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="glass-panel p-6">
          <div className="flex items-center gap-2 mb-3">
            <Shield size={18} className="text-emerald-500" />
            <span className="font-semibold text-emerald-400 text-[0.95rem]">Scope Attenuation Proof</span>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed">
            Every delegation token exchange (`/api/v1/token/delegate`) verifies that `Requested Scopes` are a strict subset (`is_subset()`) of the delegator's active scopes. Any escalation attempt (`e.g., child requesting threat:mitigate`) is blocked (`HTTP 422`).
          </p>
        </div>

        <div className="glass-panel p-6">
          <div className="flex items-center gap-2 mb-3">
            <Lock size={18} className="text-amber-500" />
            <span className="font-semibold text-amber-400 text-[0.95rem]">Ceiling Depth Enforcement</span>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed">
            To prevent runaway autonomous loops or infinite delegation chains, the `MAX_DELEGATION_DEPTH` boundary (`settings.MAX_DELEGATION_DEPTH = 5`) rejects any token grant where `current_depth + 1` exceeds the ceiling (`HTTP 403`).
          </p>
        </div>
      </div>
    </div>
  );
}
