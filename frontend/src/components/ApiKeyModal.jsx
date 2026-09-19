import React, { useState } from 'react';
import { Key, Check, Copy, AlertTriangle, X } from 'lucide-react';
import { apiService } from '../services/api.js';

export default function ApiKeyModal({ agent, onClose }) {
  const [scopes, setScopes] = useState(agent.allowed_scopes || ['tool:execute']);
  const [ttlDays, setTtlDays] = useState(90);
  const [loading, setLoading] = useState(false);
  const [issuedKey, setIssuedKey] = useState(null);
  const [copied, setCopied] = useState(false);

  const handleIssue = async () => {
    setLoading(true);
    try {
      const res = await apiService.issueApiKey(agent.id, scopes, ttlDays);
      setIssuedKey(res);
    } catch (err) {
      console.error('Issue error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    if (issuedKey?.plaintext_key) {
      navigator.clipboard.writeText(issuedKey.plaintext_key);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    }
  };

  return (
    <div className="fixed inset-0 bg-bg-deep/85 backdrop-blur-sm flex items-center justify-center z-[100] p-4">
      <div className="glass-panel w-full max-w-[560px] p-8" style={{ border: '1px solid var(--color-border-accent)' }}>
        <div className="flex justify-between items-center mb-6">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-[10px] bg-brand-red/10 border border-border-accent">
              <Key size={20} className="text-brand-red" />
            </div>
            <div>
              <h3 className="font-outfit text-xl font-bold text-ink-900">
                Issue Zero-Downtime API Key
              </h3>
              <span className="text-[0.78rem] text-text-muted">Target: {agent.name}</span>
            </div>
          </div>
          <button onClick={onClose} className="text-text-muted hover:text-ink-900 bg-transparent border-none cursor-pointer">
            <X size={20} />
          </button>
        </div>

        {!issuedKey ? (
          <div>
            <div className="mb-5">
              <label className="block text-sm font-semibold text-slate-700 mb-2">
                ReBAC Scopes to Embed
              </label>
              <div className="flex flex-wrap gap-2">
                {agent.allowed_scopes?.map((scope, idx) => (
                  <span
                    key={idx}
                    className="font-mono text-sm px-3 py-1.5 rounded-md bg-brand-red/8 text-brand-red border border-brand-red/25 font-medium"
                  >
                    {scope}
                  </span>
                ))}
              </div>
            </div>

            <div className="mb-7">
              <label className="block text-sm font-semibold text-slate-700 mb-2">
                Credential Expiration (`TTL Days`)
              </label>
              <select
                value={ttlDays}
                onChange={(e) => setTtlDays(Number(e.target.value))}
                className="w-full p-3 rounded-lg bg-surface-100 border border-slate-200 text-ink-900 text-sm"
              >
                <option value={30}>30 Days (Standard Worker)</option>
                <option value={90}>90 Days (Production Supervisor)</option>
                <option value={365}>365 Days (Long-Lived Credential)</option>
              </select>
            </div>

            <div className="bg-amber-50 border border-amber-300 p-3.5 rounded-lg flex gap-3 items-start mb-7">
              <AlertTriangle size={18} className="text-amber-600 shrink-0 mt-0.5" />
              <p className="text-sm text-amber-800 leading-relaxed">
                <strong>Zero-Plaintext Security Policy:</strong> This key (`aiiam_...`) will be displayed exactly once. Only the `bcrypt` one-way hash (`hashed_secret`) is stored in PostgreSQL.
              </p>
            </div>

            <div className="flex gap-3 justify-end">
              <button onClick={onClose} className="btn-secondary">Cancel</button>
              <button onClick={handleIssue} disabled={loading} className="btn-primary">
                {loading ? 'Generating Hash...' : 'Generate Secret Key'}
              </button>
            </div>
          </div>
        ) : (
          <div>
            <div className="bg-emerald-50 border border-emerald-300 p-4 rounded-lg mb-6">
              <div className="flex items-center gap-2 mb-2">
                <Check size={18} className="text-emerald-600" />
                <span className="font-semibold text-emerald-700 text-sm">
                  Credential Successfully Issued & Hashed
                </span>
              </div>
              <p className="text-sm text-emerald-800">
                Copy your secret key now. You will not be able to see it again after closing this window.
              </p>
            </div>

            <div className="mb-6">
              <label className="block text-xs text-text-muted mb-1.5 uppercase font-semibold">
                Plaintext Secret API Key (`aiiam_*`)
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  readOnly
                  value={issuedKey.plaintext_key}
                  className="font-mono flex-1 p-3 rounded-lg bg-surface-100 border border-border-accent text-brand-red text-sm"
                />
                <button onClick={handleCopy} className="btn-primary flex items-center gap-1.5">
                  {copied ? <Check size={16} /> : <Copy size={16} />}
                  <span>{copied ? 'Copied!' : 'Copy'}</span>
                </button>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 bg-surface-100 p-4 rounded-lg mb-7">
              <div>
                <span className="text-xs text-text-muted uppercase">Key ID</span>
                <div className="font-mono text-sm text-ink-900 font-semibold">{issuedKey.key_id}</div>
              </div>
              <div>
                <span className="text-xs text-text-muted uppercase">Key Hint</span>
                <div className="font-mono text-sm text-ink-900 font-semibold">••••{issuedKey.key_hint}</div>
              </div>
            </div>

            <button onClick={onClose} className="btn-secondary w-full">
              I have copied the key securely
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
