import React from 'react';
import { Link } from 'react-router-dom';
import PageHeader from '../components/layout/PageHeader';
import SecurityAlertsCard from '../components/SecurityAlertsCard';
import { BellRing, ShieldAlert, AlertTriangle } from 'lucide-react';

export default function AlertsPage({ apiKey, permissions }) {
  return (
    <div className="alerts-page">
      <PageHeader
        title="Security Operations Center (SOC) Alerts"
        subtitle="Real-time triage queue for regression anomalies, campaign failures, policy exceptions, and adversary attacks requiring analyst investigation."
        helpText="Alerts notify the SOC about security events, regressions, or failures requiring attention. Analysts can acknowledge alerts, investigate evidence, or promote high-severity alerts into formalized Incidents."
        actions={
          <Link
            to="/soc/incidents"
            className="btn btn-outline d-flex align-items-center gap-2 text-decoration-none"
          >
            <AlertTriangle size={14} className="text-warning" />
            <span>Go to Incidents Workspace</span>
          </Link>
        }
      />

      <SecurityAlertsCard apiKey={apiKey} />
    </div>
  );
}
