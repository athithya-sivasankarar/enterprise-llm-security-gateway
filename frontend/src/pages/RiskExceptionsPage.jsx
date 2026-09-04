import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import RiskExceptionsCard from '../components/RiskExceptionsCard';
import { ShieldAlert, AlertTriangle } from 'lucide-react';

export default function RiskExceptionsPage({ apiKey, permissions, onNavigate }) {
  return (
    <div className="risk-exceptions-page">
      <PageHeader
        title="Formal Risk Exceptions & Acceptance Lifecycle"
        subtitle="Request, review, approve, and track time-bounded business risk exceptions across AI controls and model deployments."
        helpText="A risk exception records formally accepted business risk. It does NOT disable runtime security controls. Expired or revoked exceptions automatically trigger SOC compliance alerts."
      />

      <RiskExceptionsCard apiKey={apiKey} />
    </div>
  );
}
