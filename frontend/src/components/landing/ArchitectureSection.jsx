import React from 'react';
import { Bot, KeyRound, ShieldCheck, Terminal, ScrollText, ArrowRight, Info } from 'lucide-react';

const STEPS = [
  { icon: Bot, label: 'Agent' },
  { icon: KeyRound, label: 'Token exchange (RS256)' },
  { icon: ShieldCheck, label: 'OPA policy check' },
  { icon: Terminal, label: 'MCP proxy' },
  { icon: ScrollText, label: 'Audit ledger' },
];

export default function ArchitectureSection() {
  return (
    <section id="architecture" className="max-w-6xl mx-auto px-6 py-24 scroll-mt-8">
      <div className="text-center max-w-2xl mx-auto mb-14">
        <h2 className="font-outfit text-3xl md:text-4xl font-bold text-ink-900 mb-4">
          Every action, pre-authorized and provable
        </h2>
        <p className="text-ink-600 text-lg">
          One request travels through five real, independently-enforced checkpoints
          before it ever reaches a tool.
        </p>
      </div>

      <div className="flex flex-col lg:flex-row items-stretch justify-between gap-3">
        {STEPS.map(({ icon: Icon, label }, i) => (
          <React.Fragment key={label}>
            <div className="flex-1 bg-white border border-surface-100 rounded-2xl p-5 flex flex-col items-center text-center gap-3">
              <div className="w-11 h-11 rounded-xl bg-brand-600/10 flex items-center justify-center">
                <Icon size={22} className="text-brand-600" />
              </div>
              <span className="text-sm font-semibold text-ink-900">{label}</span>
            </div>
            {i < STEPS.length - 1 && (
              <div className="hidden lg:flex items-center justify-center text-ink-600/40">
                <ArrowRight size={20} />
              </div>
            )}
          </React.Fragment>
        ))}
      </div>

      {/* Honesty constraint, carried over verbatim from the backend and
          dashboard: SPIFFE-style identifiers here are a format-checked
          string, not X.509 attestation. See backend/app/core/spiffe.py's
          module docstring for the full explanation. */}
      <div className="mt-10 max-w-3xl mx-auto flex items-start gap-3 bg-surface-100 rounded-xl p-5">
        <Info size={18} className="text-ink-600 shrink-0 mt-0.5" />
        <p className="text-sm text-ink-600 leading-relaxed">
          <strong className="text-ink-900">On identity:</strong> agent identifiers follow the
          SPIFFE URI convention (<code className="font-mono text-xs">spiffe://ai-iam.internal/ns/&lt;org&gt;/sa/&lt;agent&gt;</code>)
          for structure and readability — there is no SPIRE server or X.509
          certificate chain behind it. The actual cryptographic trust
          boundary is the RS256 JWT issued at token exchange.
        </p>
      </div>
    </section>
  );
}
