import React from 'react';
import { GitBranch, Shield, ArrowRight, CheckCircle, AlertTriangle, Lock } from 'lucide-react';

export default function DelegationChainViewer({ agents }) {
  const supervisor = agents.find((a) => !a.parent_agent_id) || agents[0];
  const children = agents.filter((a) => a.parent_agent_id === supervisor?.id) || [];

  return (
    <div>
      <div style={{ marginBottom: '2rem' }}>
        <h2 className="font-outfit" style={{ fontSize: '1.75rem', fontWeight: 700, color: '#fff' }}>
          Multi-Hop Delegation & ReBAC Trust Tree
        </h2>
        <p style={{ color: 'var(--color-text-muted)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
          Enforces Mathematical Scope Attenuation (`Child Scopes $\subseteq$ Parent Scopes`) and `MAX_DELEGATION_DEPTH` Ceilings
        </p>
      </div>

      <div className="glass-panel" style={{ padding: '2rem', marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem', borderBottom: '1px solid var(--color-border-glass)', paddingBottom: '1rem' }}>
          <GitBranch size={22} color="#00f5ff" />
          <h3 className="font-outfit" style={{ fontSize: '1.25rem', fontWeight: 600, color: '#fff' }}>
            Live Attested Delegation Chain Visualization
          </h3>
        </div>

        {/* Root Node: Supervisor */}
        {supervisor && (
          <div
            style={{
              background: 'rgba(30, 58, 138, 0.4)',
              border: '1px solid #3b82f6',
              borderRadius: '12px',
              padding: '1.25rem',
              maxWidth: '520px',
              position: 'relative',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span className="badge badge-cyan">Root Tier 0</span>
                <span style={{ fontWeight: 700, color: '#fff', fontSize: '1.05rem' }}>{supervisor.name}</span>
              </div>
              <span className="font-mono" style={{ fontSize: '0.72rem', color: '#60a5fa' }}>
                Depth: 0 / {supervisor.max_delegation_depth}
              </span>
            </div>
            <div style={{ fontSize: '0.78rem', color: '#cbd5e1', marginBottom: '0.75rem' }}>
              SPIFFE Workload SVID: <code className="font-mono" style={{ color: '#00f5ff' }}>{supervisor.spiffe_id}</code>
            </div>
            <div>
              <span style={{ fontSize: '0.7rem', color: '#94a3b8', textTransform: 'uppercase', fontWeight: 600 }}>Active Scopes:</span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', marginTop: '0.35rem' }}>
                {supervisor.allowed_scopes?.map((s, i) => (
                  <span key={i} className="font-mono" style={{ background: 'rgba(59, 130, 246, 0.2)', color: '#93c5fd', padding: '0.15rem 0.5rem', borderRadius: '4px', fontSize: '0.72rem' }}>
                    {s}
                  </span>
                ))}
              </div>
            </div>

            {/* Connecting Arrow */}
            <div style={{ position: 'absolute', bottom: '-28px', left: '40px', width: '2px', height: '28px', background: 'var(--color-border-accent)' }}></div>
          </div>
        )}

        {/* Child Tier */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', marginTop: '1.75rem', paddingLeft: '2.5rem', borderLeft: '2px dashed var(--color-border-accent)' }}>
          {children.map((child, idx) => (
            <div
              key={child.id}
              style={{
                background: 'rgba(16, 26, 56, 0.8)',
                border: '1px solid var(--color-border-glass)',
                borderRadius: '12px',
                padding: '1.25rem',
                maxWidth: '480px',
                position: 'relative',
              }}
            >
              <div style={{ position: 'absolute', top: '24px', left: '-42px', width: '40px', height: '2px', background: 'var(--color-border-accent)' }}></div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span className="badge" style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#34d399', border: '1px solid #10b981' }}>Tier 1 Delegatee</span>
                  <span style={{ fontWeight: 700, color: '#fff', fontSize: '0.98rem' }}>{child.name}</span>
                </div>
                <span className="font-mono" style={{ fontSize: '0.72rem', color: '#94a3b8' }}>
                  Depth: 1 / {child.max_delegation_depth}
                </span>
              </div>
              <div style={{ fontSize: '0.78rem', color: '#cbd5e1', marginBottom: '0.75rem' }}>
                Attestation: <code className="font-mono" style={{ color: '#00f5ff' }}>{child.spiffe_id || 'Pending Workload SVID'}</code>
              </div>
              <div>
                <span style={{ fontSize: '0.7rem', color: '#94a3b8', textTransform: 'uppercase', fontWeight: 600 }}>Attenuated Subset Scopes:</span>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', marginTop: '0.35rem' }}>
                  {child.allowed_scopes?.map((s, i) => (
                    <span key={i} className="font-mono" style={{ background: 'rgba(0, 245, 255, 0.1)', color: '#00f5ff', padding: '0.15rem 0.5rem', borderRadius: '4px', fontSize: '0.72rem' }}>
                      {s}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
            <Shield size={18} color="#10b981" />
            <span style={{ fontWeight: 600, color: '#34d399', fontSize: '0.95rem' }}>Scope Attenuation Proof</span>
          </div>
          <p style={{ fontSize: '0.82rem', color: '#cbd5e1', lineHeight: 1.6 }}>
            Every delegation token exchange (`/api/v1/token/delegate`) verifies that `Requested Scopes` are a strict subset (`is_subset()`) of the delegator's active scopes. Any escalation attempt (`e.g., child requesting threat:mitigate`) is blocked (`HTTP 422`).
          </p>
        </div>

        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
            <Lock size={18} color="#f59e0b" />
            <span style={{ fontWeight: 600, color: '#fbbf24', fontSize: '0.95rem' }}>Ceiling Depth Enforcement</span>
          </div>
          <p style={{ fontSize: '0.82rem', color: '#cbd5e1', lineHeight: 1.6 }}>
            To prevent runaway autonomous loops or infinite delegation chains, the `MAX_DELEGATION_DEPTH` boundary (`settings.MAX_DELEGATION_DEPTH = 5`) rejects any token grant where `current_depth + 1` exceeds the ceiling (`HTTP 403`).
          </p>
        </div>
      </div>
    </div>
  );
}
