import React, { useState } from 'react';
import { Cpu, Key, Shield, CheckCircle, Clock, AlertCircle, Terminal, Plus, RefreshCw } from 'lucide-react';
import { apiService } from '../services/api.js';

export default function AgentHierarchyTree({ agents, onRefresh, onOpenKeyModal }) {
  const [activatingId, setActivatingId] = useState(null);

  const handleActivate = async (agentId) => {
    setActivatingId(agentId);
    try {
      await apiService.activateAgent(agentId);
      await onRefresh();
    } catch (err) {
      console.error('Failed to activate agent:', err);
    } finally {
      setActivatingId(null);
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
        <div>
          <h2 className="font-outfit" style={{ fontSize: '1.75rem', fontWeight: 700, color: '#fff' }}>
            Autonomous Agent Hierarchy & Attestation
          </h2>
          <p style={{ color: 'var(--color-text-muted)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
            Two-Phase Workload Identity Lifecycle (`PENDING` $\rightarrow$ `ACTIVE`) with Zero-Downtime Key Rotation
          </p>
        </div>
        <button
          onClick={onRefresh}
          className="btn-secondary"
          style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
        >
          <RefreshCw size={16} color="#00f5ff" />
          <span>Refresh Cluster State</span>
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(380px, 1fr))', gap: '1.5rem' }}>
        {agents.map((agent) => {
          const isActive = agent.status === 'ACTIVE';
          return (
            <div
              key={agent.id}
              className="glass-panel"
              style={{
                padding: '1.5rem',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                borderLeft: isActive ? '4px solid #10b981' : '4px solid #f59e0b',
              }}
            >
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <div
                      style={{
                        width: '44px',
                        height: '44px',
                        borderRadius: '12px',
                        background: isActive ? 'rgba(16, 185, 129, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                        border: `1px solid ${isActive ? 'rgba(16, 185, 129, 0.4)' : 'rgba(245, 158, 11, 0.4)'}`,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                      }}
                    >
                      <Cpu size={22} color={isActive ? '#34d399' : '#fbbf24'} />
                    </div>
                    <div>
                      <h3 className="font-outfit" style={{ fontSize: '1.15rem', fontWeight: 600, color: '#fff' }}>
                        {agent.name}
                      </h3>
                      <span className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)' }}>
                        ID: {agent.id.substring(0, 12)}...
                      </span>
                    </div>
                  </div>
                  <span className={`badge ${isActive ? 'badge-active' : 'badge-pending'}`}>
                    {isActive ? <CheckCircle size={12} /> : <Clock size={12} />}
                    {agent.status}
                  </span>
                </div>

                <p style={{ fontSize: '0.85rem', color: '#cbd5e1', marginBottom: '1.25rem', lineHeight: 1.5 }}>
                  {agent.description || 'No description provided.'}
                </p>

                {/* SPIFFE Attestation SVID Card */}
                <div
                  style={{
                    background: 'rgba(6, 11, 25, 0.7)',
                    padding: '0.85rem',
                    borderRadius: '8px',
                    border: '1px solid rgba(255,255,255,0.06)',
                    marginBottom: '1.25rem',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.35rem' }}>
                    <Shield size={14} color="#00f5ff" />
                    <span style={{ fontSize: '0.72rem', fontWeight: 600, color: '#94a3b8', textTransform: 'uppercase' }}>
                      SPIFFE Workload SVID Attestation
                    </span>
                  </div>
                  <div className="font-mono" style={{ fontSize: '0.75rem', color: agent.spiffe_id ? '#00f5ff' : '#64748b', wordBreak: 'break-all' }}>
                    {agent.spiffe_id || 'Not provisioned (Awaiting Attestation Phase)'}
                  </div>
                </div>

                {/* Scopes & Max Depth Info */}
                <div style={{ marginBottom: '1.5rem' }}>
                  <div style={{ fontSize: '0.72rem', fontWeight: 600, color: '#94a3b8', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
                    Assigned ReBAC Scopes ({agent.allowed_scopes?.length || 0}) • Max Depth: {agent.max_delegation_depth}
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                    {agent.allowed_scopes?.map((scope, idx) => (
                      <span
                        key={idx}
                        className="font-mono"
                        style={{
                          background: 'rgba(0, 245, 255, 0.08)',
                          color: '#e2e8f0',
                          border: '1px solid rgba(0, 245, 255, 0.2)',
                          padding: '0.2rem 0.55rem',
                          borderRadius: '6px',
                          fontSize: '0.72rem',
                        }}
                      >
                        {scope}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div style={{ display: 'flex', gap: '0.75rem', borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: '1rem' }}>
                {!isActive ? (
                  <button
                    onClick={() => handleActivate(agent.id)}
                    disabled={activatingId === agent.id}
                    className="btn-primary"
                    style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem', fontSize: '0.85rem' }}
                  >
                    <Shield size={16} />
                    <span>{activatingId === agent.id ? 'Attesting...' : 'Activate SPIFFE ID'}</span>
                  </button>
                ) : (
                  <button
                    onClick={() => onOpenKeyModal(agent)}
                    className="btn-primary"
                    style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem', fontSize: '0.85rem' }}
                  >
                    <Key size={16} />
                    <span>Issue Zero-Downtime API Key</span>
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
