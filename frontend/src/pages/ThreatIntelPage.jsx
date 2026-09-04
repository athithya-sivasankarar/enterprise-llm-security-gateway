import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import ThreatIntelligenceCard from '../components/ThreatIntelligenceCard';
import { Globe2, ShieldAlert, BookOpen } from 'lucide-react';

export default function ThreatIntelPage({ apiKey, permissions, onNavigate }) {
  return (
    <div className="threat-intel-page">
      <PageHeader
        title="Adversarial Threat Intelligence & Taxonomy"
        subtitle="Map security observations and gateway defenses to standard industry taxonomies (OWASP Top 10 for LLM, MITRE ATLAS, CWE, and NIST AI RMF)."
        helpText="Threat intelligence maps security observations to known security frameworks and attack techniques. Reference framework mappings provide taxonomy context; they are not active system breaches unless verified by an open finding."
      />

      {/* CLARITY NOTICE BANNER */}
      <div className="card mb-4 bg-card-subtle p-4 border border-subtle">
        <div className="d-flex align-items-center gap-2 mb-1">
          <BookOpen size={16} className="text-cyan" />
          <strong className="text-xs text-uppercase text-primary">Framework Taxonomy & Reference Distinctions</strong>
        </div>
        <div className="text-xs text-muted leading-relaxed">
          The indicators below represent <strong>industry security references (OWASP LLM & MITRE ATLAS)</strong> mapped to gateway control domains.
          To see actual verified vulnerabilities in your deployment, navigate to <strong>Security Testing → Findings</strong>.
        </div>
      </div>

      <ThreatIntelligenceCard apiKey={apiKey} />
    </div>
  );
}
