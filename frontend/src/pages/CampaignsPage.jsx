import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import SecurityCampaignsCard from '../components/SecurityCampaignsCard';
import { Target, HelpCircle } from 'lucide-react';

export default function CampaignsPage({ apiKey, permissions, onNavigate }) {
  return (
    <div className="campaigns-page">
      <PageHeader
        title="Security Assessment Campaigns"
        subtitle="Organize, execute, and track automated security campaigns across gateway control suites to detect regressions against established baselines."
        helpText="A campaign is a collection of security tests executed together to evaluate gateway defenses, establish security baselines, and automatically flag regression anomalies."
      />

      <SecurityCampaignsCard role={permissions?.role} apiKey={apiKey} />
    </div>
  );
}
