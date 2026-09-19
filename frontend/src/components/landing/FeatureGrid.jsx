import React from 'react';
import { GitBranch, ShieldCheck, Terminal, Hash, KeyRound, Clock3, EyeOff, Globe2 } from 'lucide-react';

// Every card maps to a capability that's actually implemented and
// tested (see README.md's "Done" list) — nothing here is aspirational.
const FEATURES = [
  {
    icon: GitBranch,
    title: 'Server-verified delegation',
    description:
      'Multi-hop agent-to-agent delegation with real scope attenuation, cycle detection, and a depth ceiling — resolved from the verified JWT, never a caller-supplied parameter.',
  },
  {
    icon: ShieldCheck,
    title: 'Pre-execution OPA policy',
    description:
      'Every MCP tool call is evaluated by Open Policy Agent (Rego) before it executes, fail-closed on any timeout or ambiguous response.',
  },
  {
    icon: Terminal,
    title: 'SSRF-safe MCP proxy',
    description:
      'Tool server URLs are resolved server-side from an agent’s own bindings, never from the request body — plus per-server circuit breakers and response-size caps.',
  },
  {
    icon: Hash,
    title: 'Tamper-evident audit ledger',
    description:
      'SHA-256 hash-chained, append-only, written by a least-privileged Postgres role with no UPDATE/DELETE — verified continuously by a background worker.',
  },
  {
    icon: KeyRound,
    title: 'Instant, cascading revocation',
    description:
      'A Redis-backed JTI index means a suspended agent or revoked delegation grant stops working immediately, not at natural token expiry.',
  },
  {
    icon: Clock3,
    title: 'Task-scoped tokens',
    description:
      'RFC 9396 authorization_details bind a token to one specific tool call at mint time, closing the "ambient authority" gap of a session-scoped bearer token.',
  },
  {
    icon: EyeOff,
    title: 'Provenance-aware authorization',
    description:
      'If a causal trace already touched untrusted content, high-risk actions later in that same trace are denied outright — a real defense against the "lethal trifecta."',
  },
  {
    icon: Globe2,
    title: 'MCP OAuth 2.1 compliance',
    description:
      'A spec-compliant Authorization Server: RFC 8707 Resource Indicators, RFC 9207 issuer validation, discovery documents, Dynamic Client Registration.',
  },
];

export default function FeatureGrid() {
  return (
    <section className="max-w-6xl mx-auto px-6 py-24">
      <div className="text-center max-w-2xl mx-auto mb-14">
        <h2 className="font-outfit text-3xl md:text-4xl font-bold text-ink-900 mb-4">
          Every capability, actually shipped
        </h2>
        <p className="text-ink-600 text-lg">
          Not a roadmap — every claim below has a passing test and has been verified live
          against a real Postgres/OPA/Redis stack.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        {FEATURES.map(({ icon: Icon, title, description }) => (
          <div
            key={title}
            className="bg-white border border-surface-100 rounded-2xl p-6 shadow-sm hover:shadow-md transition-shadow"
          >
            <div className="w-11 h-11 rounded-xl bg-brand-600/10 flex items-center justify-center mb-4">
              <Icon size={22} className="text-brand-600" />
            </div>
            <h3 className="font-outfit text-base font-semibold text-ink-900 mb-2">{title}</h3>
            <p className="text-sm text-ink-600 leading-relaxed">{description}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
