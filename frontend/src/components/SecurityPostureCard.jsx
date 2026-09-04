import React, { useState, useEffect } from 'react';
import { dashboardApi } from '../services/dashboardApi';

export default function SecurityPostureCard({ apiKey }) {
  const [posture, setPosture] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const loadPosture = async () => {
    if (!apiKey) return;
    setLoading(true);
    setError(null);
    try {
      const data = await dashboardApi.getSecurityPosture(apiKey);
      setPosture(data);
    } catch (err) {
      setError(err.message || 'Failed to load security posture');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPosture();
    const interval = setInterval(loadPosture, 30000);
    return () => clearInterval(interval);
  }, [apiKey]);

  if (loading && !posture) {
    return <div className="card text-center text-muted">Loading Security Posture...</div>;
  }

  if (error && !posture) {
    return <div className="card text-danger">Error: {error}</div>;
  }

  if (!posture) return null;

  const getStatusBadge = (status) => {
    switch (status) {
      case 'SECURE':
        return <span className="badge badge-success" style={{ fontSize: '1rem', padding: '6px 14px' }}>🛡️ SECURE</span>;
      case 'DEGRADED':
        return <span className="badge badge-warning" style={{ fontSize: '1rem', padding: '6px 14px' }}>⚠️ DEGRADED</span>;
      case 'CRITICAL':
        return <span className="badge badge-danger" style={{ fontSize: '1rem', padding: '6px 14px' }}>🚨 CRITICAL</span>;
      default:
        return <span className="badge badge-secondary">{status}</span>;
    }
  };

  return (
    <div className="card mb-4" style={{ borderTop: `4px solid ${posture.status === 'SECURE' ? 'var(--color-success)' : posture.status === 'DEGRADED' ? 'var(--color-warning)' : 'var(--color-danger)'}` }}>
      <div className="card-header d-flex justify-content-between align-items-center">
        <div>
          <h3 className="card-title mb-1">Continuous Security Posture</h3>
          <span className="text-muted" style={{ fontSize: '0.85rem' }}>
            Real-time security health, automated campaign regressions, and active SOC alerts
          </span>
        </div>
        <div className="d-flex align-items-center gap-3">
          {getStatusBadge(posture.status)}
          <button className="btn btn-sm btn-outline" onClick={loadPosture} title="Refresh Posture">
            🔄
          </button>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-4 mt-3">
        {/* Overall Security Score */}
        <div className="metric-box" style={{ background: 'var(--bg-card-subtle)', padding: '16px', borderRadius: '8px' }}>
          <div className="text-muted" style={{ fontSize: '0.85rem' }}>Security Score</div>
          <div className="d-flex align-items-baseline gap-2 mt-1">
            <span style={{ fontSize: '1.8rem', fontWeight: 'bold', color: posture.overall_score >= 90 ? 'var(--color-success)' : posture.overall_score >= 70 ? 'var(--color-warning)' : 'var(--color-danger)' }}>
              {posture.overall_score}%
            </span>
            {posture.score_delta !== 0 && (
              <span style={{ fontSize: '0.9rem', fontWeight: 'bold', color: posture.score_delta > 0 ? 'var(--color-success)' : 'var(--color-danger)' }}>
                {posture.score_delta > 0 ? `+${posture.score_delta}%` : `${posture.score_delta}%`}
              </span>
            )}
          </div>
          <div className="text-muted mt-1" style={{ fontSize: '0.75rem' }}>
            Baseline: {posture.previous_score}%
          </div>
        </div>

        {/* Active Alerts */}
        <div className="metric-box" style={{ background: 'var(--bg-card-subtle)', padding: '16px', borderRadius: '8px' }}>
          <div className="text-muted" style={{ fontSize: '0.85rem' }}>Open SOC Alerts</div>
          <div className="d-flex align-items-baseline gap-2 mt-1">
            <span style={{ fontSize: '1.8rem', fontWeight: 'bold', color: posture.open_alerts === 0 ? 'var(--color-success)' : 'var(--color-danger)' }}>
              {posture.open_alerts}
            </span>
          </div>
          <div className="d-flex gap-2 mt-1" style={{ fontSize: '0.75rem' }}>
            <span className="text-danger font-semibold">{posture.critical_alerts} Critical</span>
            <span className="text-warning font-semibold">{posture.high_alerts} High</span>
          </div>
        </div>

        {/* Campaign Coverage */}
        <div className="metric-box" style={{ background: 'var(--bg-card-subtle)', padding: '16px', borderRadius: '8px' }}>
          <div className="text-muted" style={{ fontSize: '0.85rem' }}>Automated Coverage</div>
          <div className="d-flex align-items-baseline gap-2 mt-1">
            <span style={{ fontSize: '1.8rem', fontWeight: 'bold' }}>
              {posture.scheduled_campaigns}
            </span>
            <span className="text-muted" style={{ fontSize: '0.9rem' }}>/ {posture.active_campaigns} active campaigns</span>
          </div>
          <div className="text-muted mt-1" style={{ fontSize: '0.75rem' }}>
            Regressions Tracked: <strong className="text-warning">{posture.regressions}</strong>
          </div>
        </div>

        {/* Policy & Validation State */}
        <div className="metric-box" style={{ background: 'var(--bg-card-subtle)', padding: '16px', borderRadius: '8px' }}>
          <div className="text-muted" style={{ fontSize: '0.85rem' }}>Enforced Policy</div>
          <div className="mt-1">
            <span className="badge badge-info" style={{ fontSize: '0.95rem' }}>v{posture.policy_version}</span>
          </div>
          <div className="text-muted mt-2" style={{ fontSize: '0.75rem' }}>
            Last Validation: {posture.last_validation ? new Date(posture.last_validation).toLocaleTimeString() : 'Never'}
          </div>
        </div>
      </div>
    </div>
  );
}
