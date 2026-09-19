import React, { useState } from 'react';
import { Cpu, Key, Shield, CheckCircle, Clock, RefreshCw } from 'lucide-react';
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
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-3 mb-8">
        <div>
          <h2 className="font-outfit text-2xl md:text-3xl font-bold text-white">
            Autonomous Agent Hierarchy
          </h2>
          <p className="text-text-muted text-sm mt-1">
            Two-Phase Workload Identity Lifecycle (`PENDING` → `ACTIVE`) with Zero-Downtime Key Rotation
          </p>
        </div>
        <button onClick={onRefresh} className="btn-secondary flex items-center gap-2 self-start">
          <RefreshCw size={16} className="text-cyan-glow" />
          <span>Refresh Cluster State</span>
        </button>
      </div>

      <div className="grid gap-6" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))' }}>
        {agents.map((agent) => {
          // Pre-existing bug, found live during the frontend overhaul's
          // verification pass and fixed here (not introduced by the
          // restyle): the backend's AgentStatus enum serializes as
          // lowercase ("active"), but this comparison checked for the
          // uppercase display string instead — every real agent was
          // silently treated as pending, so "Issue API Key" could never
          // actually appear for an active agent.
          const isActive = agent.status?.toLowerCase() === 'active';
          return (
            <div
              key={agent.id}
              className={`glass-panel p-6 flex flex-col justify-between border-l-4 ${
                isActive ? 'border-l-emerald-500' : 'border-l-amber-500'
              }`}
            >
              <div>
                <div className="flex justify-between items-start mb-4">
                  <div className="flex items-center gap-3">
                    <div
                      className={`w-11 h-11 rounded-xl flex items-center justify-center ${
                        isActive
                          ? 'bg-emerald-500/15 border border-emerald-500/40'
                          : 'bg-amber-500/15 border border-amber-500/40'
                      }`}
                    >
                      <Cpu size={22} className={isActive ? 'text-emerald-400' : 'text-amber-400'} />
                    </div>
                    <div>
                      <h3 className="font-outfit text-lg font-semibold text-white">
                        {agent.name}
                      </h3>
                      <span className="font-mono text-xs text-text-muted">
                        ID: {agent.id.substring(0, 12)}...
                      </span>
                    </div>
                  </div>
                  <span className={`badge ${isActive ? 'badge-active' : 'badge-pending'}`}>
                    {isActive ? <CheckCircle size={12} /> : <Clock size={12} />}
                    {agent.status}
                  </span>
                </div>

                <p className="text-sm text-slate-300 mb-5 leading-relaxed">
                  {agent.description || 'No description provided.'}
                </p>

                {/* Format-checked identifier, not a cryptographic attestation
                    — see backend/app/core/spiffe.py's module docstring (Slice 16). */}
                <div className="bg-bg-deep/70 p-3.5 rounded-lg border border-white/5 mb-5">
                  <div className="flex items-center gap-1.5 mb-1.5">
                    <Shield size={14} className="text-cyan-glow" />
                    <span className="text-xs font-semibold text-text-muted uppercase">
                      SPIFFE-style Identifier
                    </span>
                  </div>
                  <div className={`font-mono text-sm break-all ${agent.spiffe_id ? 'text-cyan-glow' : 'text-slate-500'}`}>
                    {agent.spiffe_id || 'Not assigned (activate the agent to assign one)'}
                  </div>
                </div>

                {/* Scopes & Max Depth Info */}
                <div className="mb-6">
                  <div className="text-xs font-semibold text-text-muted uppercase mb-2">
                    Assigned ReBAC Scopes ({agent.allowed_scopes?.length || 0}) • Max Depth: {agent.max_delegation_depth}
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {agent.allowed_scopes?.map((scope, idx) => (
                      <span
                        key={idx}
                        className="font-mono text-xs bg-cyan-glow/8 text-slate-200 border border-cyan-glow/20 px-2 py-1 rounded-md"
                      >
                        {scope}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex gap-3 border-t border-white/10 pt-4">
                {!isActive ? (
                  <button
                    onClick={() => handleActivate(agent.id)}
                    disabled={activatingId === agent.id}
                    className="btn-primary flex-1 flex items-center justify-center gap-2 text-sm"
                  >
                    <Shield size={16} />
                    <span>{activatingId === agent.id ? 'Attesting...' : 'Activate SPIFFE ID'}</span>
                  </button>
                ) : (
                  <button
                    onClick={() => onOpenKeyModal(agent)}
                    className="btn-primary flex-1 flex items-center justify-center gap-2 text-sm"
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
