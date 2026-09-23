import React from 'react';

// Real, honest numbers only — no fabricated customer counts or logos.
// See README.md's own "Status" section for what each of these maps to.
const STATS = [
  { value: '24', label: 'slices shipped, live-verified' },
  { value: 'SHA-256', label: 'hash-chained audit log' },
  { value: 'Fail-closed', label: 'OPA policy enforcement' },
  { value: 'Live', label: 'tested against real Postgres/OPA/Redis' },
];

export default function TrustBar() {
  return (
    <section className="border-y border-surface-100 bg-surface-100/60">
      <div className="max-w-6xl mx-auto px-6 py-10 grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
        {STATS.map((stat) => (
          <div key={stat.label}>
            <div className="font-outfit text-2xl md:text-3xl font-bold text-brand-700">{stat.value}</div>
            <div className="text-sm text-ink-600 mt-1">{stat.label}</div>
          </div>
        ))}
      </div>
    </section>
  );
}
