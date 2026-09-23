import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { ShieldCheck, AlertOctagon, ArrowRight } from 'lucide-react';
import { apiService } from '../services/api.js';

const TOKEN_KEY = 'aiiam_operator_token';

export default function TrialSignupPage() {
  const navigate = useNavigate();
  const [orgName, setOrgName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    document.body.classList.add('on-light-surface');
    return () => document.body.classList.remove('on-light-surface');
  }, []);

  useEffect(() => {
    if (localStorage.getItem(TOKEN_KEY)) {
      navigate('/dashboard', { replace: true });
    }
  }, [navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }
    setLoading(true);
    try {
      await apiService.trialSignup(orgName, email, password);
      navigate('/dashboard', { replace: true });
    } catch (err) {
      setError(err.message || 'Signup failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4 py-12">
      <div className="w-full max-w-md">
        <Link to="/" className="flex items-center justify-center gap-2 mb-8">
          <div className="bg-gradient-to-br from-cyan-glow to-sapphire p-2 rounded-[10px] shadow-[0_0_16px_rgba(200,16,46,0.3)]">
            <ShieldCheck size={22} className="text-bg-deep" strokeWidth={2.5} />
          </div>
          <span className="font-outfit text-lg font-bold text-ink-900">
            AI-IAM <span className="text-brand-red">PLATFORM</span>
          </span>
        </Link>

        <div className="glass-panel p-8">
          <h1 className="font-outfit text-2xl font-bold text-ink-900 mb-1">Start your trial organization</h1>
          <p className="text-sm text-text-muted mb-6">
            Creates a brand new, empty organization and your own admin account — no seeded demo data, no one else's agents.
          </p>

          {error && (
            <div className="glass-panel flex items-start gap-3 p-4 mb-5 border border-rose-300" style={{ background: '#fff1f2' }} role="alert">
              <AlertOctagon size={20} className="text-rose-600 shrink-0 mt-0.5" />
              <div className="font-mono text-sm" style={{ color: '#be123c' }}>{error}</div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <div>
              <label htmlFor="orgName" className="block text-sm font-semibold text-slate-700 mb-1.5">
                Organization name
              </label>
              <input
                id="orgName"
                type="text"
                required
                minLength={2}
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                placeholder="Acme Corp"
                className="w-full p-3 rounded-lg bg-surface-100 border border-slate-200 text-ink-900 text-sm outline-none focus:border-brand-red"
              />
            </div>
            <div>
              <label htmlFor="email" className="block text-sm font-semibold text-slate-700 mb-1.5">
                Work email
              </label>
              <input
                id="email"
                type="email"
                required
                autoComplete="username"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@company.com"
                className="w-full p-3 rounded-lg bg-surface-100 border border-slate-200 text-ink-900 text-sm outline-none focus:border-brand-red"
              />
            </div>
            <div>
              <label htmlFor="password" className="block text-sm font-semibold text-slate-700 mb-1.5">
                Password
              </label>
              <input
                id="password"
                type="password"
                required
                minLength={8}
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="At least 8 characters"
                className="w-full p-3 rounded-lg bg-surface-100 border border-slate-200 text-ink-900 text-sm outline-none focus:border-brand-red"
              />
            </div>
            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-semibold text-slate-700 mb-1.5">
                Confirm password
              </label>
              <input
                id="confirmPassword"
                type="password"
                required
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full p-3 rounded-lg bg-surface-100 border border-slate-200 text-ink-900 text-sm outline-none focus:border-brand-red"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary flex items-center justify-center gap-2 mt-2"
            >
              <span>{loading ? 'Creating your org…' : 'Create trial organization'}</span>
              <ArrowRight size={16} />
            </button>
          </form>
        </div>

        <p className="text-center text-sm text-ink-600 mt-6">
          Already have an account? <Link to="/login" className="text-brand-red hover:underline">Sign in</Link>
        </p>
      </div>
    </div>
  );
}
