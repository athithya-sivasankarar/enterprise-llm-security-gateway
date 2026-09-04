import React, { useState, useEffect } from 'react';
import { dashboardApi } from '../services/dashboardApi';
import {
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Clock,
  UserCheck,
  Search,
  Plus,
  RefreshCw,
  Eye,
  SlidersHorizontal,
  XCircle,
  FileCheck2,
  ExternalLink
} from 'lucide-react';

export default function SecurityIncidentsCard({ apiKey, userRole, onSelectIncident, selectedIncidentId }) {
  const [incidents, setIncidents] = useState([]);
  const [summary, setSummary] = useState(null);
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [actionMsg, setActionMsg] = useState(null);

  // Modal State for Quick Creation
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newSeverity, setNewSeverity] = useState('MEDIUM');
  const [newPriority, setNewPriority] = useState('P2');
  const [creating, setCreating] = useState(false);

  // Quick Action Modal (Assign / Status)
  const [actionModalIncident, setActionModalIncident] = useState(null);
  const [modalActionType, setModalActionType] = useState(null); // 'ASSIGN' | 'STATUS'
  const [assigneeName, setAssigneeName] = useState('');
  const [statusChoice, setStatusChoice] = useState('INVESTIGATING');
  const [statusReason, setStatusReason] = useState('');
  const [submittingAction, setSubmittingAction] = useState(false);

  const loadIncidents = async () => {
    if (!apiKey) return;
    setLoading(true);
    setError(null);
    try {
      const [incList, summaryData] = await Promise.all([
        dashboardApi.getIncidents({ status: statusFilter || null, severity: severityFilter || null }, apiKey),
        dashboardApi.getIncidentSummary(apiKey)
      ]);
      setIncidents(incList || []);
      setSummary(summaryData || null);
    } catch (err) {
      setError(err.message || 'Failed to load incidents');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();
    const interval = setInterval(loadIncidents, 15000);
    return () => clearInterval(interval);
  }, [apiKey, statusFilter, severityFilter]);

  const handleCreateIncident = async (e) => {
    e.preventDefault();
    if (!newTitle.trim() || !newDesc.trim()) return;
    setCreating(true);
    setError(null);
    try {
      const created = await dashboardApi.createIncident({
        title: newTitle.trim(),
        description: newDesc.trim(),
        severity: newSeverity,
        priority: newPriority,
        incident_type: 'MANUAL'
      }, apiKey);
      setActionMsg(`Incident '${created.incident_id}' created successfully.`);
      setShowCreateModal(false);
      setNewTitle('');
      setNewDesc('');
      await loadIncidents();
      if (onSelectIncident) {
        onSelectIncident(created.incident_id);
      }
    } catch (err) {
      setError(err.message || 'Failed to create incident');
    } finally {
      setCreating(false);
    }
  };

  const handleResolve = async (incidentId) => {
    setError(null);
    try {
      await dashboardApi.resolveIncident(incidentId, 'Resolved from SOC Incidents table', apiKey);
      setActionMsg(`Incident '${incidentId}' marked as RESOLVED.`);
      await loadIncidents();
    } catch (err) {
      setError(err.message || 'Failed to resolve incident');
    }
  };

  const handleFalsePositive = async (incidentId) => {
    setError(null);
    try {
      await dashboardApi.markIncidentFalsePositive(incidentId, 'Marked as false positive from SOC Incidents table', apiKey);
      setActionMsg(`Incident '${incidentId}' marked as FALSE_POSITIVE.`);
      await loadIncidents();
    } catch (err) {
      setError(err.message || 'Failed to update incident');
    }
  };

  const handleExecuteModalAction = async () => {
    if (!actionModalIncident) return;
    setSubmittingAction(true);
    setError(null);
    try {
      if (modalActionType === 'ASSIGN') {
        if (!assigneeName.trim()) return;
        await dashboardApi.assignIncident(actionModalIncident.incident_id, assigneeName.trim(), apiKey);
        setActionMsg(`Assigned '${actionModalIncident.incident_id}' to ${assigneeName}.`);
      } else if (modalActionType === 'STATUS') {
        await dashboardApi.changeIncidentStatus(actionModalIncident.incident_id, statusChoice, statusReason.trim() || null, apiKey);
        setActionMsg(`Updated status of '${actionModalIncident.incident_id}' to ${statusChoice}.`);
      }
      setActionModalIncident(null);
      setModalActionType(null);
      setAssigneeName('');
      setStatusReason('');
      await loadIncidents();
    } catch (err) {
      setError(err.message || 'Action failed');
    } finally {
      setSubmittingAction(false);
    }
  };

  const getSeverityBadge = (sev) => {
    const s = String(sev).toUpperCase();
    if (s === 'CRITICAL') {
      return <span className="badge badge-error" style={{ background: 'rgba(239, 68, 68, 0.15)', color: '#ef4444', border: '1px solid rgba(239, 68, 68, 0.3)' }}>CRITICAL</span>;
    }
    if (s === 'HIGH') {
      return <span className="badge badge-warning" style={{ background: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b', border: '1px solid rgba(245, 158, 11, 0.3)' }}>HIGH</span>;
    }
    if (s === 'MEDIUM') {
      return <span className="badge badge-info" style={{ background: 'rgba(59, 130, 246, 0.15)', color: '#3b82f6', border: '1px solid rgba(59, 130, 246, 0.3)' }}>MEDIUM</span>;
    }
    return <span className="badge badge-neutral" style={{ background: 'rgba(148, 163, 184, 0.15)', color: '#94a3b8', border: '1px solid rgba(148, 163, 184, 0.3)' }}>LOW</span>;
  };

  const getStatusBadge = (st) => {
    const s = String(st).toUpperCase();
    if (s === 'OPEN') {
      return <span style={{ padding: '3px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600, background: 'rgba(239, 68, 68, 0.12)', color: '#f87171' }}>OPEN</span>;
    }
    if (s === 'INVESTIGATING') {
      return <span style={{ padding: '3px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600, background: 'rgba(245, 158, 11, 0.12)', color: '#fbbf24' }}>INVESTIGATING</span>;
    }
    if (s === 'CONTAINED') {
      return <span style={{ padding: '3px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600, background: 'rgba(168, 85, 247, 0.12)', color: '#c084fc' }}>CONTAINED</span>;
    }
    if (s === 'RESOLVED' || s === 'CLOSED') {
      return <span style={{ padding: '3px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600, background: 'rgba(34, 197, 94, 0.12)', color: '#4ade80' }}>RESOLVED</span>;
    }
    if (s === 'FALSE_POSITIVE') {
      return <span style={{ padding: '3px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600, background: 'rgba(148, 163, 184, 0.12)', color: '#94a3b8' }}>FALSE POSITIVE</span>;
    }
    return <span style={{ padding: '3px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600, background: 'rgba(148, 163, 184, 0.1)', color: '#94a3b8' }}>{s}</span>;
  };

  const getRiskScoreMeter = (score) => {
    const s = Number(score) || 0;
    const color = s >= 80 ? '#ef4444' : s >= 60 ? '#f59e0b' : s >= 30 ? '#3b82f6' : '#22c55e';
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
        <div style={{
          width: '42px',
          height: '6px',
          background: 'rgba(255, 255, 255, 0.1)',
          borderRadius: '3px',
          overflow: 'hidden'
        }}>
          <div style={{ width: `${s}%`, height: '100%', background: color }} />
        </div>
        <span style={{ fontSize: '12px', fontWeight: 700, color, fontFamily: 'var(--font-mono)' }}>{s}</span>
      </div>
    );
  };

  return (
    <div className="card" style={{ marginBottom: '24px' }}>
      <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            background: 'rgba(239, 68, 68, 0.12)',
            padding: '8px',
            borderRadius: '8px',
            color: '#f87171'
          }}>
            <ShieldAlert size={20} />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700 }}>Security Incident Case Management (Step 19)</h3>
            <p style={{ margin: '2px 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>
              Deterministic case correlation, timeline tracking, and auditable SOC responses
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            onClick={() => setShowCreateModal(true)}
            className="btn btn-secondary"
            style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', padding: '6px 12px' }}
          >
            <Plus size={14} />
            <span>New Incident</span>
          </button>
          <button
            onClick={loadIncidents}
            className="btn btn-secondary"
            disabled={loading}
            style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', padding: '6px 12px' }}
          >
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* KPI Metrics Summary Strip */}
      {summary && (
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
          gap: '12px',
          padding: '16px 20px',
          background: 'var(--bg-card-subtle)',
          borderBottom: '1px solid var(--border-subtle)'
        }}>
          <div style={{ padding: '8px 12px', background: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Open Incidents</div>
            <div style={{ fontSize: '20px', fontWeight: 700, color: summary.open_incidents > 0 ? '#f87171' : 'var(--text-primary)', marginTop: '2px' }}>
              {summary.open_incidents}
            </div>
          </div>

          <div style={{ padding: '8px 12px', background: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Critical Severity</div>
            <div style={{ fontSize: '20px', fontWeight: 700, color: summary.critical_count > 0 ? '#ef4444' : '#94a3b8', marginTop: '2px' }}>
              {summary.critical_count}
            </div>
          </div>

          <div style={{ padding: '8px 12px', background: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>High Severity</div>
            <div style={{ fontSize: '20px', fontWeight: 700, color: summary.high_count > 0 ? '#f59e0b' : '#94a3b8', marginTop: '2px' }}>
              {summary.high_count}
            </div>
          </div>

          <div style={{ padding: '8px 12px', background: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Investigating</div>
            <div style={{ fontSize: '20px', fontWeight: 700, color: '#fbbf24', marginTop: '2px' }}>
              {summary.investigating_incidents}
            </div>
          </div>

          <div style={{ padding: '8px 12px', background: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Resolved</div>
            <div style={{ fontSize: '20px', fontWeight: 700, color: '#4ade80', marginTop: '2px' }}>
              {summary.resolved_incidents}
            </div>
          </div>

          <div style={{ padding: '8px 12px', background: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Avg Risk Score</div>
            <div style={{ fontSize: '20px', fontWeight: 700, color: '#38bdf8', marginTop: '2px' }}>
              {summary.avg_risk_score}
            </div>
          </div>
        </div>
      )}

      {/* Action Messages / Alerts */}
      {actionMsg && (
        <div style={{ margin: '12px 20px 0', padding: '10px 14px', background: 'rgba(34, 197, 94, 0.1)', border: '1px solid rgba(34, 197, 94, 0.25)', borderRadius: '6px', color: '#4ade80', fontSize: '13px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>{actionMsg}</span>
          <button onClick={() => setActionMsg(null)} style={{ background: 'transparent', border: 'none', color: '#4ade80', cursor: 'pointer', fontSize: '16px' }}>&times;</button>
        </div>
      )}

      {error && (
        <div style={{ margin: '12px 20px 0', padding: '10px 14px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.25)', borderRadius: '6px', color: '#f87171', fontSize: '13px' }}>
          {error}
        </div>
      )}

      {/* Filter Controls */}
      <div style={{ padding: '12px 20px', display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: 'var(--text-muted)' }}>
          <SlidersHorizontal size={14} />
          <span>Filters:</span>
        </div>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          style={{ padding: '5px 10px', fontSize: '12px', background: 'var(--bg-card-subtle)', border: '1px solid var(--border-color)', borderRadius: '4px', color: 'var(--text-primary)' }}
        >
          <option value="">All Statuses</option>
          <option value="OPEN">Open</option>
          <option value="INVESTIGATING">Investigating</option>
          <option value="CONTAINED">Contained</option>
          <option value="RESOLVED">Resolved</option>
          <option value="CLOSED">Closed</option>
          <option value="FALSE_POSITIVE">False Positive</option>
        </select>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          style={{ padding: '5px 10px', fontSize: '12px', background: 'var(--bg-card-subtle)', border: '1px solid var(--border-color)', borderRadius: '4px', color: 'var(--text-primary)' }}
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
      </div>

      {/* Incidents Table */}
      <div className="table-container" style={{ maxHeight: '420px', overflowY: 'auto' }}>
        <table className="table" style={{ width: '100%', fontSize: '13px', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ background: 'var(--bg-card-subtle)', borderBottom: '1px solid var(--border-color)', textAlign: 'left' }}>
              <th style={{ padding: '10px 16px' }}>Incident ID</th>
              <th style={{ padding: '10px 16px' }}>Title</th>
              <th style={{ padding: '10px 16px' }}>Severity</th>
              <th style={{ padding: '10px 16px' }}>Risk Score</th>
              <th style={{ padding: '10px 16px' }}>Status</th>
              <th style={{ padding: '10px 16px' }}>Assigned To</th>
              <th style={{ padding: '10px 16px' }}>Detected</th>
              <th style={{ padding: '10px 16px', textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {incidents.length === 0 ? (
              <tr>
                <td colSpan="8" style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
                  {loading ? 'Loading incidents...' : 'No security incidents found matching criteria.'}
                </td>
              </tr>
            ) : (
              incidents.map((inc) => {
                const isSelected = selectedIncidentId === inc.incident_id;
                return (
                  <tr
                    key={inc.incident_id}
                    style={{
                      borderBottom: '1px solid var(--border-subtle)',
                      background: isSelected ? 'rgba(59, 130, 246, 0.08)' : 'transparent',
                      transition: 'background 0.15s ease'
                    }}
                  >
                    <td style={{ padding: '10px 16px', fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                      {inc.incident_id}
                    </td>
                    <td style={{ padding: '10px 16px', maxWidth: '280px' }}>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {inc.title}
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {inc.description}
                      </div>
                    </td>
                    <td style={{ padding: '10px 16px' }}>{getSeverityBadge(inc.severity)}</td>
                    <td style={{ padding: '10px 16px' }}>{getRiskScoreMeter(inc.risk_score)}</td>
                    <td style={{ padding: '10px 16px' }}>{getStatusBadge(inc.status)}</td>
                    <td style={{ padding: '10px 16px', color: 'var(--text-secondary)' }}>
                      {inc.assigned_to ? (
                        <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <UserCheck size={13} style={{ color: '#38bdf8' }} />
                          <span>{inc.assigned_to}</span>
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>Unassigned</span>
                      )}
                    </td>
                    <td style={{ padding: '10px 16px', color: 'var(--text-muted)', fontSize: '11px' }}>
                      {new Date(inc.detected_at || inc.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td style={{ padding: '10px 16px', textAlign: 'right' }}>
                      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '6px' }}>
                        <button
                          onClick={() => onSelectIncident && onSelectIncident(inc.incident_id)}
                          className="btn btn-secondary"
                          style={{ padding: '4px 8px', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '4px', background: isSelected ? 'var(--primary-color)' : undefined, color: isSelected ? '#fff' : undefined }}
                          title="Deep Investigation"
                        >
                          <Eye size={12} />
                          <span>Investigate</span>
                        </button>

                        <button
                          onClick={() => {
                            setActionModalIncident(inc);
                            setModalActionType('ASSIGN');
                            setAssigneeName(inc.assigned_to || '');
                          }}
                          className="btn btn-secondary"
                          style={{ padding: '4px 6px', fontSize: '11px' }}
                          title="Assign Analyst"
                        >
                          Assign
                        </button>

                        <button
                          onClick={() => {
                            setActionModalIncident(inc);
                            setModalActionType('STATUS');
                            setStatusChoice(inc.status);
                          }}
                          className="btn btn-secondary"
                          style={{ padding: '4px 6px', fontSize: '11px' }}
                          title="Change Status"
                        >
                          Status
                        </button>

                        {inc.status !== 'RESOLVED' && inc.status !== 'CLOSED' && (
                          <button
                            onClick={() => handleResolve(inc.incident_id)}
                            className="btn btn-secondary"
                            style={{ padding: '4px 6px', fontSize: '11px', color: '#4ade80' }}
                            title="Mark Resolved"
                          >
                            Resolve
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Quick Action Modal (Assign / Status) */}
      {actionModalIncident && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.7)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999,
          padding: '20px'
        }}>
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-color)',
            borderRadius: '8px',
            width: '100%',
            maxWidth: '440px',
            padding: '24px',
            boxShadow: 'var(--shadow-lg)'
          }}>
            <h4 style={{ margin: '0 0 12px', fontSize: '16px', fontWeight: 700 }}>
              {modalActionType === 'ASSIGN' ? `Assign Incident '${actionModalIncident.incident_id}'` : `Update Status for '${actionModalIncident.incident_id}'`}
            </h4>

            {modalActionType === 'ASSIGN' ? (
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '6px' }}>
                  Assignee Name / Email
                </label>
                <input
                  type="text"
                  placeholder="e.g. security-analyst@enterprise.com"
                  value={assigneeName}
                  onChange={(e) => setAssigneeName(e.target.value)}
                  style={{ width: '100%', padding: '8px 10px', fontSize: '13px', background: 'var(--bg-card-subtle)', border: '1px solid var(--border-color)', borderRadius: '4px', color: 'var(--text-primary)' }}
                />
              </div>
            ) : (
              <div>
                <div style={{ marginBottom: '12px' }}>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '6px' }}>
                    Target Status
                  </label>
                  <select
                    value={statusChoice}
                    onChange={(e) => setStatusChoice(e.target.value)}
                    style={{ width: '100%', padding: '8px 10px', fontSize: '13px', background: 'var(--bg-card-subtle)', border: '1px solid var(--border-color)', borderRadius: '4px', color: 'var(--text-primary)' }}
                  >
                    <option value="OPEN">OPEN</option>
                    <option value="INVESTIGATING">INVESTIGATING</option>
                    <option value="CONTAINED">CONTAINED</option>
                    <option value="RESOLVED">RESOLVED</option>
                    <option value="CLOSED">CLOSED</option>
                    <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                  </select>
                </div>

                <div style={{ marginBottom: '16px' }}>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '6px' }}>
                    Reason / Explanation (Optional)
                  </label>
                  <textarea
                    rows={3}
                    placeholder="Provide reason for state transition..."
                    value={statusReason}
                    onChange={(e) => setStatusReason(e.target.value)}
                    style={{ width: '100%', padding: '8px 10px', fontSize: '13px', background: 'var(--bg-card-subtle)', border: '1px solid var(--border-color)', borderRadius: '4px', color: 'var(--text-primary)' }}
                  />
                </div>
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button
                onClick={() => { setActionModalIncident(null); setModalActionType(null); }}
                className="btn btn-secondary"
                disabled={submittingAction}
                style={{ fontSize: '12px', padding: '6px 12px' }}
              >
                Cancel
              </button>
              <button
                onClick={handleExecuteModalAction}
                className="btn btn-primary"
                disabled={submittingAction}
                style={{ fontSize: '12px', padding: '6px 14px' }}
              >
                {submittingAction ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* New Incident Modal */}
      {showCreateModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.7)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999,
          padding: '20px'
        }}>
          <form
            onSubmit={handleCreateIncident}
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-color)',
              borderRadius: '8px',
              width: '100%',
              maxWidth: '500px',
              padding: '24px',
              boxShadow: 'var(--shadow-lg)'
            }}
          >
            <h4 style={{ margin: '0 0 16px', fontSize: '16px', fontWeight: 700 }}>
              Create Security Incident
            </h4>

            <div style={{ marginBottom: '12px' }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '6px' }}>
                Incident Title *
              </label>
              <input
                type="text"
                required
                placeholder="e.g. Prompt Injection Regression on Auth Enpoint"
                value={newTitle}
                onChange={(e) => setNewTitle(e.target.value)}
                style={{ width: '100%', padding: '8px 10px', fontSize: '13px', background: 'var(--bg-card-subtle)', border: '1px solid var(--border-color)', borderRadius: '4px', color: 'var(--text-primary)' }}
              />
            </div>

            <div style={{ marginBottom: '12px' }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '6px' }}>
                Description *
              </label>
              <textarea
                required
                rows={3}
                placeholder="Describe observations, affected components, or risk context..."
                value={newDesc}
                onChange={(e) => setNewDesc(e.target.value)}
                style={{ width: '100%', padding: '8px 10px', fontSize: '13px', background: 'var(--bg-card-subtle)', border: '1px solid var(--border-color)', borderRadius: '4px', color: 'var(--text-primary)' }}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '6px' }}>
                  Initial Severity
                </label>
                <select
                  value={newSeverity}
                  onChange={(e) => setNewSeverity(e.target.value)}
                  style={{ width: '100%', padding: '8px 10px', fontSize: '13px', background: 'var(--bg-card-subtle)', border: '1px solid var(--border-color)', borderRadius: '4px', color: 'var(--text-primary)' }}
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '6px' }}>
                  Priority
                </label>
                <select
                  value={newPriority}
                  onChange={(e) => setNewPriority(e.target.value)}
                  style={{ width: '100%', padding: '8px 10px', fontSize: '13px', background: 'var(--bg-card-subtle)', border: '1px solid var(--border-color)', borderRadius: '4px', color: 'var(--text-primary)' }}
                >
                  <option value="P1">P1 (Urgent)</option>
                  <option value="P2">P2 (High)</option>
                  <option value="P3">P3 (Normal)</option>
                  <option value="P4">P4 (Low)</option>
                </select>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="btn btn-secondary"
                disabled={creating}
                style={{ fontSize: '12px', padding: '6px 12px' }}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="btn btn-primary"
                disabled={creating}
                style={{ fontSize: '12px', padding: '6px 14px' }}
              >
                {creating ? 'Creating...' : 'Create Incident'}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
