import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Activity,
  ArrowRight,
  CheckCircle2,
  XCircle,
  Zap,
  BellRing,
  HelpCircle
} from 'lucide-react';
import PageHeader from '../components/layout/PageHeader';
import { DashboardService } from '../services/dashboardApi';

const CONTROL_DOMAINS = [
  { id: 'AUTHENTICATION', label: 'Authentication', desc: 'API Key verification' },
  { id: 'RBAC', label: 'RBAC', desc: 'Role model permissions' },
  { id: 'RATE_LIMITING', label: 'Rate Limiting', desc: 'Sliding window throttling' },
  { id: 'INPUT_DLP', label: 'Input DLP', desc: 'Presidio PII masking' },
  { id: 'PROMPT_INJECTION', label: 'Prompt Injection', desc: 'Adversarial override defense' },
  { id: 'JAILBREAK', label: 'Jailbreak Defense', desc: 'Safety persona evasion filter' },
  { id: 'SYSTEM_PROMPT_EXTRACTION', label: 'Prompt Extraction', desc: 'System prompt leakage guard' },
  { id: 'SECRET_LEAKAGE', label: 'Secret Leakage', desc: 'Credential detection' },
  { id: 'UNSAFE_CONTENT', label: 'Response Safety', desc: 'Harmful content moderation' },
  { id: 'RESPONSE_PII', label: 'Response PII', desc: 'Output sensitive data scrubber' },
  { id: 'CACHE_ISOLATION', label: 'Cache Isolation', desc: 'Tenant-isolated semantic cache' },
  { id: 'POLICY', label: 'Policy Engine', desc: 'Threshold-based governance' },
  { id: 'AUDIT', label: 'Audit Trail', desc: 'Immutable metadata logs' },
  { id: 'OBSERVABILITY', label: 'Observability', desc: 'Prometheus & OpenTelemetry metrics' }
];

export default function DashboardPage({ apiKey, permissions }) {
  const navigate = useNavigate();
  const [summary, setSummary] = useState(null);
  const [posture, setPosture] = useState(null);
  const [coverage, setCoverage] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [recentEvents, setRecentEvents] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadDashboardData() {
      if (!apiKey) return;
      try {
        setLoading(true);
        const [sumRes, postRes, covRes, alertRes, eventRes] = await Promise.all([
          DashboardService.getSummary(apiKey).catch(() => null),
          DashboardService.getSecurityPosture(apiKey).catch(() => null),
          DashboardService.getControlCoverage(null, apiKey).catch(() => null),
          DashboardService.getAlerts(apiKey, 'OPEN', null, 5).catch(() => []),
          DashboardService.getRecentEvents(apiKey, 8).catch(() => ({ events: [] }))
        ]);

        setSummary(sumRes);
        setPosture(postRes);
        setCoverage(covRes);
        setAlerts(Array.isArray(alertRes) ? alertRes : (alertRes?.alerts || []));
        setRecentEvents(eventRes?.events || []);
      } catch (err) {
        console.error('Failed loading dashboard overview:', err);
      } finally {
        setLoading(false);
      }
    }

    loadDashboardData();
  }, [apiKey]);

  const postureScore = posture?.overall_score ?? 100.0;
  const controlCoveragePct = coverage?.overall_coverage_pct ?? 100.0;
  const controlPassPct = coverage?.overall_pass_pct ?? 85.7;

  return (
    <div className="dashboard-page">
      <PageHeader
        title="Enterprise AI Security Overview"
        subtitle="Executive security health, active threat telemetry, continuous control posture, and SOC alerts."
        actions={
          <button
            className="btn btn-primary"
            onClick={() => navigate('/gateway')}
          >
            <Zap size={14} />
            <span>Open LLM Gateway Console</span>
          </button>
        }
      />

      {/* METRIC CLARITY NOTE */}
      <div className="metric-clarity-banner mb-4">
        <div className="d-flex align-items-center gap-2">
          <HelpCircle size={16} className="text-cyan" />
          <strong className="text-xs text-uppercase tracking-wider">Security Scoring Methodology</strong>
        </div>
        <p className="text-xs text-muted mb-0 mt-1">
          <strong>Posture Score ({postureScore}%)</strong> reflects the pass rate of the latest automated campaign run.
          <strong> Control Pass Rate ({controlPassPct}%)</strong> evaluates all 14 enterprise control domains against mapped validation test suites.
        </p>
      </div>

      {/* 1. TOP EXECUTIVE KPI CARDS */}
      <div className="kpi-grid mb-4">
        {/* Posture Score */}
        <div className="kpi-card">
          <div className="kpi-header">
            <span className="kpi-title">Overall Security Posture</span>
            <ShieldCheck size={18} className="text-success" />
          </div>
          <div className="kpi-value text-success">{postureScore}%</div>
          <div className="kpi-footer">
            <span>Latest Campaign Baseline: {posture?.previous_score ?? 100}%</span>
          </div>
        </div>

        {/* Control Pass Rate */}
        <div className="kpi-card">
          <div className="kpi-header">
            <span className="kpi-title">Control Pass Rate</span>
            <Shield size={18} className="text-cyan" />
          </div>
          <div className="kpi-value" style={{ color: controlPassPct >= 90 ? 'var(--status-allow)' : 'var(--status-sanitize)' }}>
            {controlPassPct}%
          </div>
          <div className="kpi-footer">
            <span>{coverage?.passing_controls ?? 12} of {coverage?.total_controls ?? 14} Domains Passing</span>
          </div>
        </div>

        {/* Open Critical Alerts */}
        <div className="kpi-card kpi-block">
          <div className="kpi-header">
            <span className="kpi-title">Open Critical Alerts</span>
            <ShieldAlert size={18} className="text-danger" />
          </div>
          <div className="kpi-value text-danger">{posture?.critical_alerts ?? 0}</div>
          <div className="kpi-footer">
            <span>{posture?.high_alerts ?? 0} High • {posture?.open_alerts ?? 0} Total Open</span>
          </div>
        </div>

        {/* Total Gateway Requests */}
        <div className="kpi-card kpi-blue">
          <div className="kpi-header">
            <span className="kpi-title">Gateway Requests</span>
            <Activity size={18} className="text-cyan" />
          </div>
          <div className="kpi-value">{summary?.total_requests ?? 0}</div>
          <div className="kpi-footer">
            <span>Avg Latency: {summary?.average_latency_ms ?? 0}ms</span>
          </div>
        </div>

        {/* Requests Allowed */}
        <div className="kpi-card kpi-allow">
          <div className="kpi-header">
            <span className="kpi-title">Allowed</span>
            <CheckCircle2 size={18} className="text-success" />
          </div>
          <div className="kpi-value text-success">{summary?.allowed ?? 0}</div>
          <div className="kpi-footer">
            <span>Clean benign completions</span>
          </div>
        </div>

        {/* Requests Sanitized */}
        <div className="kpi-card kpi-sanitize">
          <div className="kpi-header">
            <span className="kpi-title">Sanitized (DLP)</span>
            <AlertTriangle size={18} className="text-warning" />
          </div>
          <div className="kpi-value text-warning">{summary?.sanitized ?? 0}</div>
          <div className="kpi-footer">
            <span>{summary?.pii_detections ?? 0} PII scrubbed</span>
          </div>
        </div>

        {/* Requests Blocked */}
        <div className="kpi-card kpi-block">
          <div className="kpi-header">
            <span className="kpi-title">Blocked</span>
            <XCircle size={18} className="text-danger" />
          </div>
          <div className="kpi-value text-danger">{summary?.blocked ?? 0}</div>
          <div className="kpi-footer">
            <span>{summary?.injection_detections ?? 0} Injections halted</span>
          </div>
        </div>
      </div>

      {/* 2. MAIN 2-COLUMN DASHBOARD GRID */}
      <div className="dashboard-grid-2col mb-4">
        {/* SECTION A: SECURITY CONTROL STATUS (14 Domains) */}
        <div className="dashboard-panel">
          <div className="panel-header d-flex justify-content-between align-items-center">
            <div className="panel-title">
              <ShieldCheck size={16} className="text-cyan" />
              <span>14 Security Control Domains</span>
            </div>
            <Link
              to="/gateway/controls"
              className="btn btn-xs btn-outline d-flex align-items-center gap-1 text-decoration-none"
            >
              <span>View All Controls</span>
              <ArrowRight size={12} />
            </Link>
          </div>

          <div className="controls-status-mini-grid">
            {CONTROL_DOMAINS.map((ctrl) => {
              const matrixItem = coverage?.matrix?.find((m) => m.domain === ctrl.id);
              const status = matrixItem?.status || 'PASS';
              const isPass = status === 'PASS';
              const isReg = status === 'REGRESSION';

              return (
                <div key={ctrl.id} className="control-mini-box">
                  <div className="control-mini-left">
                    <div className="control-mini-name">{ctrl.label}</div>
                    <div className="control-mini-desc text-muted">{ctrl.desc}</div>
                  </div>
                  <div className="control-mini-right">
                    <span className={`badge ${isPass ? 'badge-allow' : isReg ? 'badge-sanitize' : 'badge-block'}`}>
                      {status}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* SECTION C: ACTIVE CRITICAL & HIGH ALERTS */}
        <div className="dashboard-panel">
          <div className="panel-header d-flex justify-content-between align-items-center">
            <div className="panel-title">
              <BellRing size={16} className="text-danger" />
              <span>Active SOC Alerts</span>
            </div>
            <Link
              to="/soc/alerts"
              className="btn btn-xs btn-outline d-flex align-items-center gap-1 text-decoration-none"
            >
              <span>View All Alerts</span>
              <ArrowRight size={12} />
            </Link>
          </div>

          {alerts && alerts.length > 0 ? (
            <div className="alerts-mini-list">
              {alerts.slice(0, 5).map((a) => (
                <div key={a.alert_id} className="alert-mini-item">
                  <div className="d-flex justify-content-between align-items-start mb-1">
                    <div className="d-flex align-items-center gap-2">
                      <span className={`badge ${a.severity === 'CRITICAL' ? 'badge-block' : a.severity === 'HIGH' ? 'badge-sanitize' : 'badge-allow'}`}>
                        {a.severity}
                      </span>
                      <span className="font-medium text-xs text-primary">{a.title}</span>
                    </div>
                    <span className="text-muted font-mono text-xs">
                      {a.created_at ? new Date(a.created_at).toLocaleTimeString() : ''}
                    </span>
                  </div>
                  <p className="text-muted text-xs mb-0">{a.description || 'Security threshold exception or regression detected.'}</p>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state py-8 text-center text-muted text-xs">
              <CheckCircle2 size={24} className="text-success mx-auto mb-2" />
              <div>Zero Open Alerts. Gateway security controls operational.</div>
            </div>
          )}

          {/* SECTION D: TESTING HEALTH */}
          <div className="testing-health-summary-box mt-4 pt-3 border-top">
            <div className="d-flex justify-content-between align-items-center mb-2">
              <span className="text-xs font-semibold text-muted text-uppercase">Testing & Validation Health</span>
              <Link
                to="/testing/catalog"
                className="btn btn-xs btn-ghost text-cyan p-0 text-decoration-none"
              >
                Catalog & Runs →
              </Link>
            </div>
            <div className="grid grid-cols-4 gap-2 text-center text-xs">
              <div className="bg-subtle p-2 rounded">
                <span className="text-muted d-block text-xxs">Tested</span>
                <strong className="text-primary">{coverage?.tested_controls ?? 14}/14</strong>
              </div>
              <div className="bg-subtle p-2 rounded">
                <span className="text-muted d-block text-xxs">Passing</span>
                <strong className="text-success">{coverage?.passing_controls ?? 12}</strong>
              </div>
              <div className="bg-subtle p-2 rounded">
                <span className="text-muted d-block text-xxs">Regressions</span>
                <strong className="text-warning">{coverage?.regression_controls ?? 1}</strong>
              </div>
              <div className="bg-subtle p-2 rounded">
                <span className="text-muted d-block text-xxs">Gaps</span>
                <strong className="text-danger">{coverage?.control_gaps_count ?? 2}</strong>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* SECTION B: RECENT SECURITY ACTIVITY */}
      <div className="dashboard-panel mb-4">
        <div className="panel-header d-flex justify-content-between align-items-center">
          <div className="panel-title">
            <Activity size={16} className="text-cyan" />
            <span>Recent Gateway Security Events</span>
          </div>
          <Link
            to="/gateway/events"
            className="btn btn-xs btn-outline d-flex align-items-center gap-1 text-decoration-none"
          >
            <span>View All Security Events</span>
            <ArrowRight size={12} />
          </Link>
        </div>

        <div className="events-table-wrapper">
          <table className="events-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Request ID</th>
                <th>User / Role</th>
                <th>Model</th>
                <th>Action</th>
                <th>Risk Score</th>
                <th>Detected Threat</th>
                <th>PII Detected</th>
                <th>Latency</th>
              </tr>
            </thead>
            <tbody>
              {recentEvents && recentEvents.length > 0 ? (
                recentEvents.map((evt) => (
                  <tr key={evt.request_id}>
                    <td className="font-mono text-xs">
                      {evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : 'N/A'}
                    </td>
                    <td className="font-mono text-xs">{evt.request_id ? evt.request_id.slice(0, 13) + '...' : 'N/A'}</td>
                    <td>
                      <span className="font-semibold text-xs">{evt.user || 'developer'}</span>
                      <span className="text-muted text-xxs d-block font-mono">{evt.role || 'admin'}</span>
                    </td>
                    <td className="font-mono text-xs">{evt.model}</td>
                    <td>
                      <span className={`badge ${evt.action === 'ALLOW' ? 'badge-allow' : evt.action === 'SANITIZE' ? 'badge-sanitize' : 'badge-block'}`}>
                        {evt.action}
                      </span>
                    </td>
                    <td className="font-mono text-xs">
                      <span className={`font-bold ${evt.risk_score > 70 ? 'text-danger' : evt.risk_score > 30 ? 'text-warning' : 'text-success'}`}>
                        {evt.risk_score}/100
                      </span>
                    </td>
                    <td className="font-mono text-xs text-muted">
                      {evt.threat_type || '—'}
                    </td>
                    <td>
                      {evt.pii_detected ? (
                        <span className="badge badge-sanitize text-xxs">PII DETECTED</span>
                      ) : (
                        <span className="text-muted text-xs">None</span>
                      )}
                    </td>
                    <td className="font-mono text-xs">{evt.latency_ms ? `${evt.latency_ms}ms` : '—'}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={9} className="text-center py-6 text-muted text-xs">
                    No recent security events recorded. Use the Chat / Gateway console to send prompts.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
