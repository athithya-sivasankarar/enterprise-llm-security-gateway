import React, { useState, useEffect } from 'react';
import { dashboardApi } from '../services/dashboardApi';
import {
  ShieldAlert,
  Clock,
  FileText,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  Send,
  Plus,
  RefreshCw,
  Hash,
  User,
  Activity,
  Layers,
  ChevronRight,
  Info,
  Sliders,
  CheckSquare,
  Lock,
  Tag,
  Copy,
  ExternalLink
} from 'lucide-react';

export default function IncidentInvestigationCard({ apiKey, userRole, incidentId, onClose }) {
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [actionMsg, setActionMsg] = useState(null);
  const [activeTab, setActiveTab] = useState('timeline'); // 'timeline' | 'evidence' | 'alerts' | 'findings' | 'notes' | 'actions'

  // New Note State
  const [noteContent, setNoteContent] = useState('');
  const [submittingNote, setSubmittingNote] = useState(false);

  // New Evidence Modal State
  const [showEvidenceModal, setShowEvidenceModal] = useState(false);
  const [evType, setEvType] = useState('MANUAL');
  const [evDesc, setEvDesc] = useState('');
  const [evContent, setEvContent] = useState('');
  const [submittingEvidence, setSubmittingEvidence] = useState(false);

  // Action State
  const [showActionModal, setShowActionModal] = useState(false);
  const [selectedActionType, setSelectedActionType] = useState('REQUEST_POLICY_REVIEW');
  const [actionDescription, setActionDescription] = useState('');
  const [submittingAction, setSubmittingAction] = useState(false);

  const loadDetail = async () => {
    if (!incidentId || !apiKey) return;
    setLoading(true);
    setError(null);
    try {
      const res = await dashboardApi.getIncident(incidentId, apiKey);
      setDetail(res);
    } catch (err) {
      setError(err.message || 'Failed to load incident investigation details');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDetail();
  }, [incidentId, apiKey]);

  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!noteContent.trim()) return;
    setSubmittingNote(true);
    setError(null);
    try {
      await dashboardApi.addIncidentNote(incidentId, noteContent.trim(), apiKey);
      setNoteContent('');
      setActionMsg('Analyst note appended and sanitized successfully.');
      await loadDetail();
    } catch (err) {
      setError(err.message || 'Failed to add note');
    } finally {
      setSubmittingNote(false);
    }
  };

  const handleAttachEvidence = async (e) => {
    e.preventDefault();
    if (!evDesc.trim()) return;
    setSubmittingEvidence(true);
    setError(null);
    try {
      await dashboardApi.attachIncidentEvidence(incidentId, {
        evidence_type: evType,
        description: evDesc.trim(),
        raw_content: evContent.trim() || null
      }, apiKey);
      setShowEvidenceModal(false);
      setEvDesc('');
      setEvContent('');
      setActionMsg('Evidence artifact attached with SHA-256 integrity hash.');
      await loadDetail();
    } catch (err) {
      setError(err.message || 'Failed to attach evidence');
    } finally {
      setSubmittingEvidence(false);
    }
  };

  const handleRecordAction = async (e) => {
    e.preventDefault();
    if (!actionDescription.trim()) return;
    setSubmittingAction(true);
    setError(null);
    try {
      await dashboardApi.recordIncidentAction(incidentId, {
        action_type: selectedActionType,
        description: actionDescription.trim()
      }, apiKey);
      setShowActionModal(false);
      setActionDescription('');
      setActionMsg(`Controlled SOC Action '${selectedActionType}' executed and recorded to audit log.`);
      await loadDetail();
    } catch (err) {
      setError(err.message || 'Action failed');
    } finally {
      setSubmittingAction(false);
    }
  };

  if (!incidentId) {
    return (
      <div className="card" style={{ marginBottom: '24px', padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
        <ShieldAlert size={36} style={{ margin: '0 auto 12px', opacity: 0.5 }} />
        <h4 style={{ margin: '0 0 6px', fontSize: '15px', color: 'var(--text-secondary)' }}>No Incident Selected for Deep Investigation</h4>
        <p style={{ margin: 0, fontSize: '13px' }}>Select an incident from the Case Management table above to inspect the chronological timeline, evidence artifacts, and response actions.</p>
      </div>
    );
  }

  const inc = detail?.incident;

  const getRiskScoreMeter = (score) => {
    const s = Number(score) || 0;
    const color = s >= 80 ? '#ef4444' : s >= 60 ? '#f59e0b' : s >= 30 ? '#3b82f6' : '#22c55e';
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <div style={{
          width: '60px',
          height: '8px',
          background: 'rgba(255, 255, 255, 0.1)',
          borderRadius: '4px',
          overflow: 'hidden'
        }}>
          <div style={{ width: `${s}%`, height: '100%', background: color }} />
        </div>
        <span style={{ fontSize: '14px', fontWeight: 700, color, fontFamily: 'var(--font-mono)' }}>{s}/100</span>
      </div>
    );
  };

  return (
    <div className="card" style={{ marginBottom: '24px', border: '1px solid rgba(59, 130, 246, 0.3)' }}>
      {/* Header Bar */}
      <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', background: 'rgba(59, 130, 246, 0.05)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            background: 'rgba(59, 130, 246, 0.15)',
            padding: '8px',
            borderRadius: '8px',
            color: '#38bdf8'
          }}>
            <ShieldAlert size={20} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#38bdf8', fontWeight: 600 }}>{inc?.incident_id || incidentId}</span>
              <span style={{ fontSize: '11px', padding: '2px 6px', borderRadius: '4px', background: 'var(--bg-card-subtle)', color: 'var(--text-muted)' }}>Policy: v{inc?.policy_version || '1.0.0'}</span>
            </div>
            <h3 style={{ margin: '2px 0 0', fontSize: '16px', fontWeight: 700 }}>{inc?.title || 'Loading Incident Investigation...'}</h3>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            onClick={() => setShowActionModal(true)}
            className="btn btn-primary"
            style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', padding: '6px 12px' }}
          >
            <Sliders size={14} />
            <span>Response Action</span>
          </button>
          <button
            onClick={loadDetail}
            className="btn btn-secondary"
            disabled={loading}
            style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', padding: '6px 12px' }}
          >
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
            <span>Refresh</span>
          </button>
          {onClose && (
            <button
              onClick={onClose}
              className="btn btn-secondary"
              style={{ fontSize: '12px', padding: '6px 10px' }}
            >
              Close
            </button>
          )}
        </div>
      </div>

      {/* Incident Metadata Key Strip */}
      {inc && (
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
          gap: '12px',
          padding: '14px 20px',
          background: 'var(--bg-card-subtle)',
          borderBottom: '1px solid var(--border-subtle)'
        }}>
          <div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Severity</div>
            <div style={{ fontSize: '13px', fontWeight: 700, marginTop: '2px', color: inc.severity === 'CRITICAL' ? '#ef4444' : inc.severity === 'HIGH' ? '#f59e0b' : '#38bdf8' }}>
              {inc.severity}
            </div>
          </div>

          <div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Risk Score</div>
            <div style={{ marginTop: '2px' }}>{getRiskScoreMeter(inc.risk_score)}</div>
          </div>

          <div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Status</div>
            <div style={{ fontSize: '13px', fontWeight: 700, marginTop: '2px', color: inc.status === 'OPEN' ? '#f87171' : inc.status === 'RESOLVED' ? '#4ade80' : '#fbbf24' }}>
              {inc.status}
            </div>
          </div>

          <div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Priority</div>
            <div style={{ fontSize: '13px', fontWeight: 700, marginTop: '2px', color: 'var(--text-primary)' }}>
              {inc.priority}
            </div>
          </div>

          <div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Assigned To</div>
            <div style={{ fontSize: '13px', fontWeight: 600, marginTop: '2px', color: 'var(--text-primary)' }}>
              {inc.assigned_to || <span style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>Unassigned</span>}
            </div>
          </div>

          <div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Detected At</div>
            <div style={{ fontSize: '12px', marginTop: '2px', color: 'var(--text-muted)' }}>
              {new Date(inc.detected_at).toLocaleString()}
            </div>
          </div>
        </div>
      )}

      {/* Safety Invariant Notice */}
      <div style={{
        margin: '12px 20px',
        padding: '10px 14px',
        background: 'rgba(59, 130, 246, 0.08)',
        border: '1px solid rgba(59, 130, 246, 0.2)',
        borderRadius: '6px',
        fontSize: '12px',
        color: '#93c5fd',
        display: 'flex',
        alignItems: 'center',
        gap: '8px'
      }}>
        <Info size={16} style={{ flexShrink: 0 }} />
        <span>
          <strong>SOC Invariant:</strong> Incident response actions are strictly auditable workflows. The platform operates on sanitized metadata only and cannot disable security controls (DLP, RBAC, Prompt-Injection, Rate-Limiting, Output Filtering).
        </span>
      </div>

      {/* Action Messages / Alerts */}
      {actionMsg && (
        <div style={{ margin: '0 20px 12px', padding: '10px 14px', background: 'rgba(34, 197, 94, 0.1)', border: '1px solid rgba(34, 197, 94, 0.25)', borderRadius: '6px', color: '#4ade80', fontSize: '13px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>{actionMsg}</span>
          <button onClick={() => setActionMsg(null)} style={{ background: 'transparent', border: 'none', color: '#4ade80', cursor: 'pointer', fontSize: '16px' }}>&times;</button>
        </div>
      )}

      {error && (
        <div style={{ margin: '0 20px 12px', padding: '10px 14px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.25)', borderRadius: '6px', color: '#f87171', fontSize: '13px' }}>
          {error}
        </div>
      )}

      {/* Navigation Tabs */}
      <div style={{
        display: 'flex',
        borderBottom: '1px solid var(--border-color)',
        padding: '0 20px',
        gap: '8px',
        overflowX: 'auto'
      }}>
        {[
          { id: 'timeline', label: `Timeline (${detail?.timeline?.length || 0})`, icon: Clock },
          { id: 'evidence', label: `Evidence (${detail?.evidence?.length || 0})`, icon: FileCheck2 },
          { id: 'alerts', label: `Related Alerts & Runs (${(detail?.related_alerts?.length || 0) + (detail?.related_campaign_run ? 1 : 0)})`, icon: Activity },
          { id: 'findings', label: `Findings (${detail?.findings?.length || 0})`, icon: AlertTriangle },
          { id: 'notes', label: `Analyst Notes (${detail?.notes?.length || 0})`, icon: FileText },
          { id: 'actions', label: `Response Actions (${detail?.actions?.length || 0})`, icon: Sliders }
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '10px 14px',
                fontSize: '12px',
                fontWeight: isActive ? 700 : 500,
                color: isActive ? 'var(--primary-color)' : 'var(--text-secondary)',
                borderBottom: isActive ? '2px solid var(--primary-color)' : '2px solid transparent',
                background: 'transparent',
                border: 'none',
                cursor: 'pointer',
                whiteSpace: 'nowrap'
              }}
            >
              <Icon size={14} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab Panels */}
      <div style={{ padding: '20px' }}>
        {/* TAB 1: TIMELINE */}
        {activeTab === 'timeline' && (
          <div>
            {detail?.timeline?.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)', fontSize: '13px' }}>
                No chronological events recorded yet.
              </div>
            ) : (
              <div style={{ position: 'relative', paddingLeft: '24px' }}>
                <div style={{
                  position: 'absolute',
                  top: '10px',
                  bottom: '10px',
                  left: '7px',
                  width: '2px',
                  background: 'var(--border-color)'
                }} />

                {detail?.timeline?.map((ev, idx) => (
                  <div key={idx} style={{ position: 'relative', marginBottom: '20px' }}>
                    <div style={{
                      position: 'absolute',
                      left: '-24px',
                      top: '2px',
                      width: '16px',
                      height: '16px',
                      borderRadius: '50%',
                      background: ev.event_type.includes('REGRESSION') || ev.severity === 'CRITICAL' ? '#ef4444' : ev.event_type.includes('RESOLVED') ? '#22c55e' : '#38bdf8',
                      border: '3px solid var(--bg-card)',
                      boxShadow: '0 0 0 1px var(--border-color)'
                    }} />

                    <div style={{
                      background: 'var(--bg-card-subtle)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: '6px',
                      padding: '12px 16px'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px', flexWrap: 'wrap', gap: '8px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span style={{ fontSize: '11px', fontWeight: 700, padding: '2px 6px', borderRadius: '4px', background: 'rgba(59, 130, 246, 0.12)', color: '#38bdf8' }}>
                            {ev.event_type}
                          </span>
                          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Source: {ev.source}</span>
                        </div>
                        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                          {new Date(ev.timestamp).toLocaleString()}
                        </span>
                      </div>
                      <div style={{ fontSize: '13px', color: 'var(--text-primary)', lineHeight: 1.5 }}>
                        {ev.description}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* TAB 2: EVIDENCE */}
        {activeTab === 'evidence' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
              <h4 style={{ margin: 0, fontSize: '14px', fontWeight: 700 }}>Attached Evidence Artifacts</h4>
              <button
                onClick={() => setShowEvidenceModal(true)}
                className="btn btn-secondary"
                style={{ fontSize: '11px', padding: '5px 10px', display: 'flex', alignItems: 'center', gap: '4px' }}
              >
                <Plus size={12} />
                <span>Attach Evidence</span>
              </button>
            </div>

            {detail?.evidence?.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)', fontSize: '13px' }}>
                No evidence items attached yet. Click "Attach Evidence" to add test runs or sanitized reports.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {detail?.evidence?.map((evd) => (
                  <div
                    key={evd.evidence_id}
                    style={{
                      background: 'var(--bg-card-subtle)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: '6px',
                      padding: '12px 16px'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px', flexWrap: 'wrap', gap: '8px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontSize: '11px', fontWeight: 600, padding: '2px 6px', borderRadius: '4px', background: 'rgba(34, 197, 94, 0.12)', color: '#4ade80' }}>
                          {evd.evidence_type}
                        </span>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                          ID: {evd.evidence_id}
                        </span>
                      </div>
                      <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                        {new Date(evd.created_at).toLocaleString()}
                      </span>
                    </div>

                    <div style={{ fontSize: '13px', color: 'var(--text-primary)', marginBottom: '8px' }}>
                      {evd.description}
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      <Hash size={12} />
                      <span>SHA-256: {evd.sha256_hash}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* TAB 3: RELATED ALERTS & RUNS */}
        {activeTab === 'alerts' && (
          <div>
            <div style={{ marginBottom: '18px' }}>
              <h4 style={{ margin: '0 0 10px', fontSize: '14px', fontWeight: 700 }}>Linked Security Campaign Run</h4>
              {detail?.related_campaign_run ? (
                <div style={{ background: 'var(--bg-card-subtle)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '14px' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '10px' }}>
                    <div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Run ID</div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 600 }}>{detail.related_campaign_run.campaign_run_id}</div>
                    </div>
                    <div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Security Score</div>
                      <div style={{ fontSize: '14px', fontWeight: 700, color: '#38bdf8' }}>{detail.related_campaign_run.security_score}%</div>
                    </div>
                    <div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Baseline Score</div>
                      <div style={{ fontSize: '14px', fontWeight: 700 }}>{detail.related_campaign_run.baseline_score ?? 'N/A'}%</div>
                    </div>
                    <div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Score Delta</div>
                      <div style={{ fontSize: '14px', fontWeight: 700, color: (detail.related_campaign_run.score_delta || 0) < 0 ? '#ef4444' : '#22c55e' }}>
                        {detail.related_campaign_run.score_delta ? `${detail.related_campaign_run.score_delta}%` : '0%'}
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div style={{ color: 'var(--text-muted)', fontSize: '13px' }}>No direct campaign run associated.</div>
              )}
            </div>

            <div>
              <h4 style={{ margin: '0 0 10px', fontSize: '14px', fontWeight: 700 }}>Correlated Security Alerts</h4>
              {detail?.related_alerts?.length === 0 ? (
                <div style={{ color: 'var(--text-muted)', fontSize: '13px' }}>No related alerts found.</div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {detail?.related_alerts?.map((alt) => (
                    <div key={alt.alert_id} style={{ background: 'var(--bg-card-subtle)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '10px 14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div>
                        <div style={{ fontWeight: 600, fontSize: '13px' }}>{alt.title}</div>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>ID: {alt.alert_id} | Type: {alt.alert_type}</div>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontSize: '11px', fontWeight: 600, color: alt.severity === 'CRITICAL' ? '#ef4444' : alt.severity === 'HIGH' ? '#f59e0b' : '#38bdf8' }}>{alt.severity}</span>
                        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{alt.status}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 4: FINDINGS */}
        {activeTab === 'findings' && (
          <div>
            <h4 style={{ margin: '0 0 12px', fontSize: '14px', fontWeight: 700 }}>Security Control Regressions & Findings</h4>
            {detail?.findings?.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)', fontSize: '13px' }}>
                No specific control regressions recorded for this incident.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {detail?.findings?.map((f) => (
                  <div key={f.id} style={{ background: 'var(--bg-card-subtle)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '12px 14px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                      <span style={{ fontWeight: 600, fontSize: '13px' }}>Test: {f.test_id} ({f.category})</span>
                      <span style={{ fontSize: '11px', fontWeight: 700, color: f.severity === 'CRITICAL' ? '#ef4444' : f.severity === 'HIGH' ? '#f59e0b' : '#38bdf8' }}>{f.severity}</span>
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{f.description}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* TAB 5: ANALYST NOTES */}
        {activeTab === 'notes' && (
          <div>
            <h4 style={{ margin: '0 0 12px', fontSize: '14px', fontWeight: 700 }}>Analyst Investigation Observations</h4>

            <form onSubmit={handleAddNote} style={{ marginBottom: '20px' }}>
              <textarea
                rows={3}
                required
                placeholder="Add sanitized investigation findings, observations, or response context..."
                value={noteContent}
                onChange={(e) => setNoteContent(e.target.value)}
                style={{ width: '100%', padding: '10px', fontSize: '13px', background: 'var(--bg-card-subtle)', border: '1px solid var(--border-color)', borderRadius: '6px', color: 'var(--text-primary)', marginBottom: '8px' }}
              />
              <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={submittingNote}
                  style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', padding: '6px 14px' }}
                >
                  <Send size={13} />
                  <span>{submittingNote ? 'Saving...' : 'Add Note'}</span>
                </button>
              </div>
            </form>

            {detail?.notes?.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '16px', color: 'var(--text-muted)', fontSize: '13px' }}>
                No analyst notes recorded yet.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {detail?.notes?.map((n) => (
                  <div key={n.note_id} style={{ background: 'var(--bg-card-subtle)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '12px 14px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px', fontSize: '11px', color: 'var(--text-muted)' }}>
                      <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{n.author}</span>
                      <span>{new Date(n.created_at).toLocaleString()}</span>
                    </div>
                    <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                      {n.note}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* TAB 6: RESPONSE ACTIONS */}
        {activeTab === 'actions' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
              <h4 style={{ margin: 0, fontSize: '14px', fontWeight: 700 }}>Controlled SOC Response Log</h4>
              <button
                onClick={() => setShowActionModal(true)}
                className="btn btn-primary"
                style={{ fontSize: '11px', padding: '5px 10px', display: 'flex', alignItems: 'center', gap: '4px' }}
              >
                <Plus size={12} />
                <span>Execute Action</span>
              </button>
            </div>

            {detail?.actions?.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)', fontSize: '13px' }}>
                No controlled response actions recorded yet.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {detail?.actions?.map((act) => (
                  <div key={act.action_id} style={{ background: 'var(--bg-card-subtle)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '12px 14px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px', flexWrap: 'wrap', gap: '8px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontSize: '11px', fontWeight: 700, padding: '2px 6px', borderRadius: '4px', background: 'rgba(168, 85, 247, 0.12)', color: '#c084fc' }}>
                          {act.action_type}
                        </span>
                        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Status: {act.status}</span>
                      </div>
                      <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                        {new Date(act.created_at).toLocaleString()}
                      </span>
                    </div>
                    <div style={{ fontSize: '13px', color: 'var(--text-primary)', marginBottom: '4px' }}>
                      {act.description}
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      Requested by: {act.requested_by} | Approved by: {act.approved_by || act.requested_by}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Response Action Trigger Modal */}
      {showActionModal && (
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
            onSubmit={handleRecordAction}
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-color)',
              borderRadius: '8px',
              width: '100%',
              maxWidth: '460px',
              padding: '24px',
              boxShadow: 'var(--shadow-lg)'
            }}
          >
            <h4 style={{ margin: '0 0 12px', fontSize: '16px', fontWeight: 700 }}>
              Trigger Controlled Response Action
            </h4>

            <div style={{ marginBottom: '14px' }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '6px' }}>
                Action Type *
              </label>
              <select
                value={selectedActionType}
                onChange={(e) => setSelectedActionType(e.target.value)}
                style={{ width: '100%', padding: '8px 10px', fontSize: '13px', background: 'var(--bg-card-subtle)', border: '1px solid var(--border-color)', borderRadius: '4px', color: 'var(--text-primary)' }}
              >
                <option value="REQUEST_POLICY_REVIEW">REQUEST_POLICY_REVIEW (Security Team Assessment)</option>
                <option value="ACKNOWLEDGE_ALERT">ACKNOWLEDGE_ALERT (SOC Confirmation)</option>
                <option value="ASSIGN_INCIDENT">ASSIGN_INCIDENT (Route to Tier-2)</option>
                <option value="CHANGE_STATUS">CHANGE_STATUS (Update Case State)</option>
                <option value="ATTACH_EVIDENCE">ATTACH_EVIDENCE (Attach Artifact)</option>
                <option value="ATTACH_REPORT">ATTACH_REPORT (Link Security Report)</option>
                <option value="MARK_FALSE_POSITIVE">MARK_FALSE_POSITIVE (Dismiss Finding)</option>
              </select>
            </div>

            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '6px' }}>
                Action Rationale / Description *
              </label>
              <textarea
                required
                rows={3}
                placeholder="Explain the security rationale and context..."
                value={actionDescription}
                onChange={(e) => setActionDescription(e.target.value)}
                style={{ width: '100%', padding: '8px 10px', fontSize: '13px', background: 'var(--bg-card-subtle)', border: '1px solid var(--border-color)', borderRadius: '4px', color: 'var(--text-primary)' }}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button
                type="button"
                onClick={() => setShowActionModal(false)}
                className="btn btn-secondary"
                disabled={submittingAction}
                style={{ fontSize: '12px', padding: '6px 12px' }}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="btn btn-primary"
                disabled={submittingAction}
                style={{ fontSize: '12px', padding: '6px 14px' }}
              >
                {submittingAction ? 'Executing...' : 'Confirm Action'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Attach Evidence Modal */}
      {showEvidenceModal && (
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
            onSubmit={handleAttachEvidence}
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-color)',
              borderRadius: '8px',
              width: '100%',
              maxWidth: '480px',
              padding: '24px',
              boxShadow: 'var(--shadow-lg)'
            }}
          >
            <h4 style={{ margin: '0 0 14px', fontSize: '16px', fontWeight: 700 }}>
              Attach Evidence Artifact
            </h4>

            <div style={{ marginBottom: '12px' }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '6px' }}>
                Evidence Type
              </label>
              <select
                value={evType}
                onChange={(e) => setEvType(e.target.value)}
                style={{ width: '100%', padding: '8px 10px', fontSize: '13px', background: 'var(--bg-card-subtle)', border: '1px solid var(--border-color)', borderRadius: '4px', color: 'var(--text-primary)' }}
              >
                <option value="MANUAL">MANUAL (Analyst Evidence Note)</option>
                <option value="SECURITY_TEST_RESULT">SECURITY_TEST_RESULT</option>
                <option value="FINDING">FINDING</option>
                <option value="REGRESSION">REGRESSION</option>
                <option value="REPORT">REPORT</option>
                <option value="AUDIT_METADATA">AUDIT_METADATA</option>
              </select>
            </div>

            <div style={{ marginBottom: '12px' }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '6px' }}>
                Description *
              </label>
              <input
                type="text"
                required
                placeholder="e.g. Validation test run finding log artifact"
                value={evDesc}
                onChange={(e) => setEvDesc(e.target.value)}
                style={{ width: '100%', padding: '8px 10px', fontSize: '13px', background: 'var(--bg-card-subtle)', border: '1px solid var(--border-color)', borderRadius: '4px', color: 'var(--text-primary)' }}
              />
            </div>

            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '6px' }}>
                Sanitized Payload / Summary (Optional)
              </label>
              <textarea
                rows={3}
                placeholder="Paste sanitized metadata..."
                value={evContent}
                onChange={(e) => setEvContent(e.target.value)}
                style={{ width: '100%', padding: '8px 10px', fontSize: '13px', background: 'var(--bg-card-subtle)', border: '1px solid var(--border-color)', borderRadius: '4px', color: 'var(--text-primary)' }}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button
                type="button"
                onClick={() => setShowEvidenceModal(false)}
                className="btn btn-secondary"
                disabled={submittingEvidence}
                style={{ fontSize: '12px', padding: '6px 12px' }}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="btn btn-primary"
                disabled={submittingEvidence}
                style={{ fontSize: '12px', padding: '6px 14px' }}
              >
                {submittingEvidence ? 'Hashing & Attaching...' : 'Attach Evidence'}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
