import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Play,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  FileCheck,
  Layers,
  ChevronDown,
  ChevronUp,
  Activity,
  Terminal
} from 'lucide-react';
import { DashboardService } from '../services/dashboardApi';

const CATEGORIES = [
  { id: 'AUTHENTICATION', label: 'Authentication' },
  { id: 'RBAC', label: 'RBAC Access' },
  { id: 'RATE_LIMITING', label: 'Rate Limiting' },
  { id: 'INPUT_DLP', label: 'Input DLP' },
  { id: 'PROMPT_INJECTION', label: 'Prompt Injection' },
  { id: 'JAILBREAK', label: 'Jailbreak' },
  { id: 'SYSTEM_PROMPT_EXTRACTION', label: 'Prompt Extraction' },
  { id: 'SECRET_LEAKAGE', label: 'Secret Leakage' },
  { id: 'UNSAFE_CONTENT', label: 'Unsafe Content' },
  { id: 'RESPONSE_PII', label: 'Response PII' },
  { id: 'CACHE_ISOLATION', label: 'Cache Isolation' },
  { id: 'POLICY', label: 'Policy Engine' },
  { id: 'AUDIT', label: 'Audit Logging' },
  { id: 'OBSERVABILITY', label: 'Observability' },
];

export default function SecurityValidationCard({ role, apiKey }) {
  const [latestReport, setLatestReport] = useState(null);
  const [runs, setRuns] = useState([]);
  const [findings, setFindings] = useState([]);
  const [isRunning, setIsRunning] = useState(false);
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [error, setError] = useState(null);
  const [expandedFinding, setExpandedFinding] = useState(null);
  const [showFindings, setShowFindings] = useState(true);

  const canRunTests = role && (role.toLowerCase() === 'admin' || role.toLowerCase() === 'analyst');

  const fetchValidationData = async () => {
    try {
      const [runsData, findingsData] = await Promise.all([
        DashboardService.getSecurityTestRuns(apiKey).catch(() => []),
        DashboardService.getSecurityFindings(apiKey).catch(() => [])
      ]);

      setRuns(runsData || []);
      setFindings(findingsData || []);

      if (runsData && runsData.length > 0) {
        const latestRunId = runsData[0].run_id;
        const report = await DashboardService.getSecurityTestReport(latestRunId, apiKey).catch(() => null);
        if (report) {
          setLatestReport(report);
        }
      }
    } catch (err) {
      console.error('Failed to load validation data:', err);
    }
  };

  useEffect(() => {
    fetchValidationData();
  }, [apiKey]);

  const handleRunValidation = async () => {
    if (!canRunTests || isRunning) return;
    setIsRunning(true);
    setError(null);

    const payload = selectedCategory === 'ALL' ? {} : { categories: [selectedCategory] };

    try {
      const report = await DashboardService.runSecurityTests(payload, apiKey);
      setLatestReport(report);
      await fetchValidationData();
    } catch (err) {
      setError(err.message || 'Validation run failed');
    } finally {
      setIsRunning(false);
    }
  };

  const score = latestReport ? latestReport.security_score : 100.0;
  const scoreColor = score >= 90 ? 'var(--status-allow)' : score >= 70 ? 'var(--status-sanitize)' : 'var(--status-block)';

  return (
    <div className="card security-validation-card" style={{ marginBottom: '24px' }}>
      {/* Header */}
      <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
            <ShieldAlert className="icon text-primary" size={20} />
            Automated Security Validation & Red-Team Engine
          </h3>
          <p className="card-subtitle" style={{ margin: '4px 0 0 0', color: 'var(--text-muted)' }}>
            Deterministic QA validation verifying gateway controls against synthetic adversarial threats (Mock Model default)
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            disabled={isRunning}
            style={{
              background: 'var(--bg-card-subtle)',
              color: 'var(--text-primary)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
              padding: '6px 12px',
              fontSize: '13px',
              outline: 'none'
            }}
          >
            <option value="ALL">All 14 Categories</option>
            {CATEGORIES.map(c => (
              <option key={c.id} value={c.id}>{c.label}</option>
            ))}
          </select>

          <button
            onClick={handleRunValidation}
            disabled={!canRunTests || isRunning}
            className="btn btn-primary"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '7px 16px',
              fontWeight: 600,
              fontSize: '13px',
              cursor: canRunTests && !isRunning ? 'pointer' : 'not-allowed',
              opacity: canRunTests && !isRunning ? 1 : 0.6
            }}
            title={!canRunTests ? 'Requires Admin or Analyst role' : 'Run security validation suite'}
          >
            {isRunning ? (
              <>
                <RefreshCw size={14} className="spin-animation" />
                Validating Controls...
              </>
            ) : (
              <>
                <Play size={14} />
                Run Validation Suite
              </>
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="error-banner" style={{ margin: '12px 0' }}>
          <AlertTriangle size={16} />
          <span>{error}</span>
        </div>
      )}

      {/* KPI Overview Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
        gap: '16px',
        margin: '16px 0 20px'
      }}>
        <div style={{
          background: 'var(--bg-card-subtle)',
          padding: '16px',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border-subtle)',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center'
        }}>
          <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
            Security Health Score
          </div>
          <div style={{ fontSize: '32px', fontWeight: 800, color: scoreColor, fontFamily: 'var(--font-mono)' }}>
            {score.toFixed(1)}%
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            {latestReport ? `${latestReport.summary.passed_tests}/${latestReport.summary.total_tests} Assertions Passed` : 'Ready to run'}
          </div>
        </div>

        <div style={{
          background: 'var(--bg-card-subtle)',
          padding: '16px',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border-subtle)'
        }}>
          <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '10px' }}>
            Last Validation Run
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '13px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Status:</span>
              <span style={{ fontWeight: 600, color: latestReport?.status === 'COMPLETED' ? 'var(--status-allow)' : 'var(--status-sanitize)' }}>
                {latestReport ? latestReport.status : 'NO RUNS'}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Policy Version:</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>v{latestReport ? latestReport.policy_version : '1.0.0'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Run ID:</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{latestReport ? latestReport.run_id : 'N/A'}</span>
            </div>
          </div>
        </div>

        <div style={{
          background: 'var(--bg-card-subtle)',
          padding: '16px',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border-subtle)'
        }}>
          <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '10px' }}>
            Results Breakdown
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--status-allow)' }}>
              <CheckCircle2 size={14} />
              <span>Passed: <strong>{latestReport ? latestReport.summary.passed_tests : 0}</strong></span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--status-block)' }}>
              <XCircle size={14} />
              <span>Failed: <strong>{latestReport ? latestReport.summary.failed_tests : 0}</strong></span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--status-sanitize)' }}>
              <AlertTriangle size={14} />
              <span>Errors: <strong>{latestReport ? latestReport.summary.error_tests : 0}</strong></span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-muted)' }}>
              <Layers size={14} />
              <span>Total: <strong>{latestReport ? latestReport.summary.total_tests : 0}</strong></span>
            </div>
          </div>
        </div>

        <div style={{
          background: 'var(--bg-card-subtle)',
          padding: '16px',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border-subtle)'
        }}>
          <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '10px' }}>
            Active Findings
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '13px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#ef4444' }}>Critical:</span>
              <strong>{findings.filter(f => f.severity === 'CRITICAL').length}</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#f97316' }}>High:</span>
              <strong>{findings.filter(f => f.severity === 'HIGH').length}</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#eab308' }}>Medium:</span>
              <strong>{findings.filter(f => f.severity === 'MEDIUM').length}</strong>
            </div>
          </div>
        </div>
      </div>

      {/* Category Breakdown Matrix */}
      {latestReport && latestReport.category_summaries && (
        <div style={{ marginBottom: '20px' }}>
          <div style={{ fontSize: '13px', fontWeight: 600, marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Activity size={16} className="text-primary" />
            Category Coverage & Pass Rates
          </div>
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
            gap: '10px'
          }}>
            {latestReport.category_summaries.map((cat, idx) => (
              <div
                key={idx}
                style={{
                  background: 'rgba(255, 255, 255, 0.02)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '10px 12px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}
              >
                <div>
                  <div style={{ fontSize: '12px', fontWeight: 600 }}>{cat.category}</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    {cat.passed}/{cat.total} passed
                  </div>
                </div>
                <div style={{
                  fontSize: '12px',
                  fontWeight: 700,
                  fontFamily: 'var(--font-mono)',
                  color: cat.pass_rate === 100 ? 'var(--status-allow)' : cat.pass_rate >= 80 ? 'var(--status-sanitize)' : 'var(--status-block)'
                }}>
                  {cat.pass_rate.toFixed(0)}%
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Findings Accordion */}
      {findings && findings.length > 0 && (
        <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '16px' }}>
          <div
            onClick={() => setShowFindings(!showFindings)}
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              cursor: 'pointer',
              marginBottom: '12px'
            }}
          >
            <span style={{ fontSize: '13px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
              <ShieldAlert size={16} color="#ef4444" />
              Security Validation Findings ({findings.length})
            </span>
            {showFindings ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </div>

          {showFindings && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {findings.slice(0, 10).map((f) => {
                const isExp = expandedFinding === f.finding_id;
                const badgeBg = f.severity === 'CRITICAL' ? 'rgba(239, 68, 68, 0.2)' : f.severity === 'HIGH' ? 'rgba(249, 115, 22, 0.2)' : 'rgba(234, 179, 8, 0.2)';
                const badgeColor = f.severity === 'CRITICAL' ? '#ef4444' : f.severity === 'HIGH' ? '#f97316' : '#eab308';

                return (
                  <div
                    key={f.finding_id}
                    style={{
                      background: 'rgba(255, 255, 255, 0.02)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-sm)',
                      padding: '10px 14px'
                    }}
                  >
                    <div
                      onClick={() => setExpandedFinding(isExp ? null : f.finding_id)}
                      style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <span style={{
                          fontSize: '10px',
                          fontWeight: 700,
                          padding: '2px 6px',
                          borderRadius: '4px',
                          background: badgeBg,
                          color: badgeColor
                        }}>
                          {f.severity}
                        </span>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-muted)' }}>
                          {f.test_id}
                        </span>
                        <span style={{ fontSize: '13px', fontWeight: 500 }}>
                          {f.title}
                        </span>
                      </div>
                      <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                        {f.category}
                      </span>
                    </div>

                    {isExp && (
                      <div style={{ marginTop: '10px', paddingTop: '10px', borderTop: '1px dashed var(--border-subtle)', fontSize: '12px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                        <div><strong style={{ color: 'var(--text-muted)' }}>Description:</strong> {f.description}</div>
                        <div><strong style={{ color: 'var(--status-allow)' }}>Expected:</strong> {f.expected_behavior}</div>
                        <div><strong style={{ color: 'var(--status-block)' }}>Actual:</strong> {f.actual_behavior}</div>
                        <div><strong style={{ color: 'var(--text-muted)' }}>Endpoint:</strong> {f.endpoint} | <strong style={{ color: 'var(--text-muted)' }}>Policy:</strong> v{f.policy_version}</div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
