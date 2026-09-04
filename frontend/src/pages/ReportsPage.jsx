import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import SecurityReportsCard from '../components/SecurityReportsCard';
import { FileText, ShieldCheck } from 'lucide-react';

export default function ReportsPage({ apiKey, permissions, onNavigate }) {
  return (
    <div className="reports-page">
      <PageHeader
        title="Compliance Evidence & Security Reports"
        subtitle="Generate, verify, and export tamper-evident security reports for SOC 2, ISO 27001, OWASP LLM, and NIST AI RMF audit compliance."
        helpText="Reports summarize security testing results, evidence, findings, and compliance mappings with SHA-256 cryptographic integrity verification."
      />

      <SecurityReportsCard apiKey={apiKey} userRole={permissions?.role} />
    </div>
  );
}
