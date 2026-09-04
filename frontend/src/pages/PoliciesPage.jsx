import React, { useState, useEffect } from 'react';
import PageHeader from '../components/layout/PageHeader';
import SecurityPolicyCard from '../components/SecurityPolicyCard';
import { Sliders, RefreshCw } from 'lucide-react';
import { DashboardService } from '../services/dashboardApi';

export default function PoliciesPage({ apiKey, permissions, onNavigate }) {
  const [activePolicy, setActivePolicy] = useState(null);
  const [policyHistory, setPolicyHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  const loadPolicyData = async () => {
    try {
      setLoading(true);
      const [active, history] = await Promise.all([
        DashboardService.getActivePolicy(apiKey).catch(() => null),
        DashboardService.getPolicyHistory(apiKey).catch(() => ({ history: [] }))
      ]);
      setActivePolicy(active);
      setPolicyHistory(history?.history || []);
    } catch (err) {
      console.error('Failed to load policies:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPolicyData();
  }, [apiKey]);

  return (
    <div className="policies-page">
      <PageHeader
        title="Dynamic Security Policy Engine"
        subtitle="Configure real-time thresholds for DLP inspection, prompt injection classifiers, rate limiting windows, and model authorization allowlists."
        helpText="Policy updates are validated against strict JSON schemas and hot-reloaded into Redis cache and PostgreSQL without requiring gateway restarts."
        actions={
          <button className="btn btn-outline" onClick={loadPolicyData} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'spin-icon' : ''} />
            <span>Reload Policy</span>
          </button>
        }
      />

      {activePolicy ? (
        <SecurityPolicyCard
          activePolicy={activePolicy}
          history={policyHistory}
          role={permissions?.role}
          apiKey={apiKey}
          onPolicyChanged={loadPolicyData}
        />
      ) : (
        <div className="card text-center py-10 text-muted text-xs">
          Loading active policy configuration...
        </div>
      )}
    </div>
  );
}
