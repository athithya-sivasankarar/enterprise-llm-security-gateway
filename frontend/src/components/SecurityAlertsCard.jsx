import React, { useState, useEffect } from 'react';
import { dashboardApi } from '../services/dashboardApi';

export default function SecurityAlertsCard({ apiKey }) {
  const [alerts, setAlerts] = useState([]);
  const [summary, setSummary] = useState(null);
  const [statusFilter, setStatusFilter] = useState('OPEN');
  const [severityFilter, setSeverityFilter] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [actionMsg, setActionMsg] = useState(null);

  const loadAlerts = async () => {
    if (!apiKey) return;
    setLoading(true);
    setError(null);
    try {
      const [alertList, summaryData] = await Promise.all([
        dashboardApi.getAlerts(apiKey, statusFilter || null, severityFilter || null),
        dashboardApi.getAlertSummary(apiKey)
      ]);
      setAlerts(alertList || []);
      setSummary(summaryData || null);
    } catch (err) {
      setError(err.message || 'Failed to load alerts');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
    const interval = setInterval(loadAlerts, 30000);
    return () => clearInterval(interval);
  }, [apiKey, statusFilter, severityFilter]);

  const handleAcknowledge = async (alertId) => {
    setError(null);
    try {
      await dashboardApi.acknowledgeAlert(alertId, apiKey);
      setActionMsg(`Acknowledged alert '${alertId}'.`);
      await loadAlerts();
    } catch (err) {
      setError(err.message || 'Failed to acknowledge alert');
    }
  };

  const handleResolve = async (alertId) => {
    setError(null);
    try {
      await dashboardApi.resolveAlert(alertId, apiKey);
      setActionMsg(`Resolved alert '${alertId}'.`);
      await loadAlerts();
    } catch (err) {
      setError(err.message || 'Failed to resolve alert');
    }
  };

  const getSeverityBadge = (sev) => {
    switch (sev) {
      case 'CRITICAL':
        return <span className="badge badge-danger">CRITICAL</span>;
      case 'HIGH':
        return <span className="badge badge-warning">HIGH</span>;
      case 'MEDIUM':
        return <span className="badge badge-info">MEDIUM</span>;
      case 'LOW':
        return <span className="badge badge-secondary">LOW</span>;
      default:
        return <span className="badge badge-secondary">{sev}</span>;
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'OPEN':
        return <span className="badge badge-danger">● OPEN</span>;
      case 'ACKNOWLEDGED':
        return <span className="badge badge-warning">◐ ACKNOWLEDGED</span>;
      case 'RESOLVED':
        return <span className="badge badge-success">✓ RESOLVED</span>;
      default:
        return <span className="badge badge-secondary">{status}</span>;
    }
  };

  return (
    <div className="card mb-4">
      <div className="card-header d-flex justify-content-between align-items-center">
        <div>
          <h3 className="card-title mb-1">SOC Security Alerts & Degradation Triage</h3>
          <span className="text-muted" style={{ fontSize: '0.85rem' }}>
            Actionable incident notifications generated from campaign regressions, score degradation, and failures
          </span>
        </div>
        <div className="d-flex align-items-center gap-2">
          {summary && (
            <div className="d-flex gap-2 mr-2" style={{ fontSize: '0.85rem' }}>
              <span className="badge badge-danger">{summary.critical_count} Critical</span>
              <span className="badge badge-warning">{summary.high_count} High</span>
              <span className="badge badge-secondary">{summary.open_alerts} Open Total</span>
            </div>
          )}
          <button className="btn btn-sm btn-outline" onClick={loadAlerts} title="Refresh Alerts">
            🔄
          </button>
        </div>
      </div>

      {/* Filters Bar */}
      <div className="d-flex flex-wrap gap-2 p-3 border-bottom align-items-center" style={{ background: 'var(--bg-card-subtle)' }}>
        <div className="d-flex align-items-center gap-1">
          <span className="text-muted mr-1" style={{ fontSize: '0.8rem' }}>Status:</span>
          {['OPEN', 'ACKNOWLEDGED', 'RESOLVED', ''].map((st) => (
            <button
              key={st || 'ALL'}
              className={`btn btn-xs ${statusFilter === st ? 'btn-primary' : 'btn-outline'}`}
              onClick={() => setStatusFilter(st)}
            >
              {st || 'ALL'}
            </button>
          ))}
        </div>

        <div className="d-flex align-items-center gap-1 ml-auto">
          <span className="text-muted mr-1" style={{ fontSize: '0.8rem' }}>Severity:</span>
          {['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev || 'ALL'}
              className={`btn btn-xs ${severityFilter === sev ? 'btn-primary' : 'btn-outline'}`}
              onClick={() => setSeverityFilter(sev)}
            >
              {sev || 'ALL'}
            </button>
          ))}
        </div>
      </div>

      {actionMsg && (
        <div className="alert alert-info py-2 px-3 m-3 d-flex justify-content-between align-items-center" style={{ fontSize: '0.85rem' }}>
          <span>ℹ️ {actionMsg}</span>
          <button className="btn-close" onClick={() => setActionMsg(null)}>×</button>
        </div>
      )}

      {error && (
        <div className="alert alert-danger py-2 px-3 m-3 d-flex justify-content-between align-items-center" style={{ fontSize: '0.85rem' }}>
          <span>⚠️ {error}</span>
          <button className="btn-close" onClick={() => setError(null)}>×</button>
        </div>
      )}

      {loading && alerts.length === 0 ? (
        <div className="text-center py-4 text-muted">Loading alerts...</div>
      ) : alerts.length === 0 ? (
        <div className="text-center py-4 text-muted">
          No security alerts matching the current filter.
        </div>
      ) : (
        <div className="table-responsive">
          <table className="table table-hover align-middle mb-0">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Alert Title & Details</th>
                <th>Type / Campaign</th>
                <th>Status</th>
                <th>Created</th>
                <th className="text-end">Triage Actions</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((a) => (
                <tr key={a.alert_id}>
                  <td>{getSeverityBadge(a.severity)}</td>
                  <td style={{ maxWidth: '400px' }}>
                    <div className="font-semibold">{a.title}</div>
                    <div className="text-muted mt-1" style={{ fontSize: '0.8rem', lineHeight: '1.3' }}>
                      {a.description}
                    </div>
                    {a.score_delta !== null && a.score_delta !== undefined && (
                      <div className="mt-1" style={{ fontSize: '0.75rem' }}>
                        <span className="badge badge-sm badge-secondary mr-2">Score: {a.score}%</span>
                        <span className={`badge badge-sm ${a.score_delta < 0 ? 'badge-danger' : 'badge-success'}`}>
                          Delta: {a.score_delta}%
                        </span>
                      </div>
                    )}
                  </td>
                  <td>
                    <div className="font-mono" style={{ fontSize: '0.8rem' }}>{a.alert_type}</div>
                    <small className="text-muted">{a.campaign_id}</small>
                  </td>
                  <td>
                    {getStatusBadge(a.status)}
                    {a.acknowledged_by && (
                      <div className="text-muted mt-1" style={{ fontSize: '0.7rem' }}>
                        Ack by {a.acknowledged_by}
                      </div>
                    )}
                    {a.resolved_by && (
                      <div className="text-muted mt-1" style={{ fontSize: '0.7rem' }}>
                        Res by {a.resolved_by}
                      </div>
                    )}
                  </td>
                  <td>
                    <span className="font-mono text-muted" style={{ fontSize: '0.8rem' }}>
                      {new Date(a.created_at).toLocaleString()}
                    </span>
                  </td>
                  <td className="text-end">
                    <div className="d-flex justify-content-end gap-1">
                      {a.status === 'OPEN' && (
                        <button
                          className="btn btn-sm btn-outline-warning"
                          onClick={() => handleAcknowledge(a.alert_id)}
                          style={{ fontSize: '0.75rem' }}
                        >
                          Acknowledge
                        </button>
                      )}
                      {a.status !== 'RESOLVED' && (
                        <button
                          className="btn btn-sm btn-outline-success"
                          onClick={() => handleResolve(a.alert_id)}
                          style={{ fontSize: '0.75rem' }}
                        >
                          Resolve
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
