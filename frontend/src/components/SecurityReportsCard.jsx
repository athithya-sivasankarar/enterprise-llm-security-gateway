import React, { useState, useEffect } from 'react';
import { dashboardApi } from '../services/dashboardApi';

export default function SecurityReportsCard({ apiKey, userRole }) {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selectedReport, setSelectedReport] = useState(null);
  const [evidenceItems, setEvidenceItems] = useState([]);
  const [loadingEvidence, setLoadingEvidence] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [verifyResult, setVerifyResult] = useState(null);
  const [verifying, setVerifying] = useState(false);
  const [typeFilter, setTypeFilter] = useState('');

  // Form State
  const [formData, setFormData] = useState({
    report_type: 'CAMPAIGN',
    title: '',
    description: '',
    campaign_id: ''
  });
  const [campaigns, setCampaigns] = useState([]);

  const isRestricted = userRole === 'developer';

  const fetchReports = async () => {
    if (isRestricted) return;
    setLoading(true);
    setError(null);
    try {
      const data = await dashboardApi.getReports(typeFilter ? { report_type: typeFilter } : {}, apiKey);
      setReports(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err.message || 'Failed to load security reports');
    } finally {
      setLoading(false);
    }
  };

  const fetchCampaigns = async () => {
    if (isRestricted) return;
    try {
      const data = await dashboardApi.getCampaigns(apiKey);
      setCampaigns(Array.isArray(data) ? data : []);
    } catch (e) {
      // safe fallback
    }
  };

  useEffect(() => {
    fetchReports();
    fetchCampaigns();
  }, [apiKey, userRole, typeFilter]);

  const handleCreateReport = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await dashboardApi.createReport(formData, apiKey);
      setShowCreateModal(false);
      setFormData({ report_type: 'CAMPAIGN', title: '', description: '', campaign_id: '' });
      await fetchReports();
    } catch (err) {
      setError(err.message || 'Failed to generate security report');
    } finally {
      setLoading(false);
    }
  };

  const handleViewDetails = async (reportId) => {
    setLoadingEvidence(true);
    try {
      const rep = await dashboardApi.getReport(reportId, apiKey);
      setSelectedReport(rep);
      const ev = await dashboardApi.getReportEvidence(reportId, 100, apiKey);
      setEvidenceItems(Array.isArray(ev) ? ev : []);
    } catch (err) {
      setError(err.message || 'Failed to retrieve report details');
    } finally {
      setLoadingEvidence(false);
    }
  };

  const handleVerifyIntegrity = async (reportId) => {
    setVerifying(true);
    setVerifyResult(null);
    try {
      const res = await dashboardApi.verifyReport(reportId, apiKey);
      setVerifyResult(res);
    } catch (err) {
      setVerifyResult({ valid: false, message: err.message || 'Verification failed' });
    } finally {
      setVerifying(false);
    }
  };

  const handleExport = async (reportId, format) => {
    try {
      const token = apiKey || 'dev-key-12345';
      const url = `/api/reports/${reportId}/export?format=${format}`;
      const res = await fetch(url, {
        headers: { 'X-API-Key': token }
      });
      if (!res.ok) throw new Error(`Export failed with HTTP ${res.status}`);
      
      const blob = await res.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = `${reportId}.${format === 'markdown' ? 'md' : format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(downloadUrl);
    } catch (err) {
      setError(err.message || `Export ${format.toUpperCase()} failed`);
    }
  };

  const handleDelete = async (reportId) => {
    if (!window.confirm(`Delete report ${reportId}?`)) return;
    try {
      await dashboardApi.deleteReport(reportId, apiKey);
      if (selectedReport?.report_id === reportId) setSelectedReport(null);
      await fetchReports();
    } catch (err) {
      setError(err.message || 'Failed to delete report');
    }
  };

  if (isRestricted) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl mb-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <span className="text-xl">📊</span>
            <h2 className="text-lg font-bold text-slate-100">Security Assessment Reports & Evidence</h2>
          </div>
          <span className="text-xs bg-amber-500/10 text-amber-400 px-2.5 py-1 rounded border border-amber-500/20 font-mono">
            Role: Developer (Restricted)
          </span>
        </div>
        <p className="text-sm text-slate-400 mt-4">
          Report generation and audit evidence inspection require <code className="text-cyan-400">admin</code> or <code className="text-cyan-400">analyst</code> privileges (HTTP 403 Forbidden).
        </p>
      </div>
    );
  }

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl mb-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center space-x-3">
            <span className="text-2xl">📋</span>
            <h2 className="text-lg font-bold text-slate-100">Security Assessment Reports & Compliance Evidence</h2>
            <span className="text-xs bg-cyan-500/10 text-cyan-400 px-2.5 py-0.5 rounded border border-cyan-500/20 font-mono">
              Step 18 Engine
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Auditable security reports, normalized control evidence, framework mappings (OWASP/MITRE/NIST), and SHA-256 tamper verification.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="bg-slate-800 border border-slate-700 text-xs text-slate-200 rounded px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Report Types</option>
            <option value="CAMPAIGN">Campaign Reports</option>
            <option value="SECURITY_VALIDATION">Validation Reports</option>
            <option value="EXECUTIVE">Executive Reports</option>
            <option value="COMPLIANCE">Compliance Reports</option>
          </select>

          <button
            onClick={() => setShowCreateModal(true)}
            className="px-3.5 py-1.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold rounded shadow transition"
          >
            + Generate Report
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-900/40 border border-red-700/50 rounded-lg text-xs text-red-300 flex justify-between items-center">
          <span>⚠️ {error}</span>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-200">✕</button>
        </div>
      )}

      {/* Reports Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-slate-950/60 text-slate-400 border-b border-slate-800">
              <th className="py-2.5 px-3 font-semibold">Report ID</th>
              <th className="py-2.5 px-3 font-semibold">Type</th>
              <th className="py-2.5 px-3 font-semibold">Title</th>
              <th className="py-2.5 px-3 font-semibold">Score</th>
              <th className="py-2.5 px-3 font-semibold">Regressions</th>
              <th className="py-2.5 px-3 font-semibold">Findings (C/H/M/L)</th>
              <th className="py-2.5 px-3 font-semibold">Created</th>
              <th className="py-2.5 px-3 font-semibold text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {reports.length === 0 ? (
              <tr>
                <td colSpan="8" className="text-center py-6 text-slate-500 font-sans">
                  {loading ? 'Generating/fetching reports...' : 'No security assessment reports generated yet.'}
                </td>
              </tr>
            ) : (
              reports.map((rep) => (
                <tr key={rep.report_id} className="hover:bg-slate-800/40 transition">
                  <td className="py-2.5 px-3 text-cyan-400 font-semibold">{rep.report_id}</td>
                  <td className="py-2.5 px-3">
                    <span className="text-[11px] px-2 py-0.5 bg-slate-800 text-slate-300 rounded border border-slate-700">
                      {rep.report_type}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-200 font-sans max-w-[200px] truncate" title={rep.title}>
                    {rep.title}
                  </td>
                  <td className="py-2.5 px-3">
                    <span className={`font-bold ${rep.security_score >= 90 ? 'text-emerald-400' : rep.security_score >= 70 ? 'text-amber-400' : 'text-red-400'}`}>
                      {rep.security_score}%
                    </span>
                  </td>
                  <td className="py-2.5 px-3">
                    {rep.regression_count > 0 ? (
                      <span className="text-red-400 font-bold">⚠️ {rep.regression_count}</span>
                    ) : (
                      <span className="text-emerald-400 font-medium">0</span>
                    )}
                  </td>
                  <td className="py-2.5 px-3 text-slate-300">
                    <span className="text-red-400 font-semibold">{rep.critical_findings}</span> /{' '}
                    <span className="text-amber-400 font-semibold">{rep.high_findings}</span> /{' '}
                    <span className="text-yellow-400">{rep.medium_findings}</span> /{' '}
                    <span className="text-slate-400">{rep.low_findings}</span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                    {new Date(rep.created_at).toLocaleDateString()} {new Date(rep.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </td>
                  <td className="py-2.5 px-3 text-right space-x-1">
                    <button
                      onClick={() => handleViewDetails(rep.report_id)}
                      className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-400 rounded text-[11px] transition"
                      title="View Details & Evidence"
                    >
                      View
                    </button>
                    <button
                      onClick={() => handleExport(rep.report_id, 'pdf')}
                      className="px-2 py-1 bg-red-950/60 hover:bg-red-900/80 text-red-300 rounded text-[11px] transition border border-red-800/40"
                      title="Export PDF"
                    >
                      PDF
                    </button>
                    <button
                      onClick={() => handleExport(rep.report_id, 'json')}
                      className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[11px] transition"
                      title="Export JSON"
                    >
                      JSON
                    </button>
                    <button
                      onClick={() => handleExport(rep.report_id, 'markdown')}
                      className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[11px] transition"
                      title="Export Markdown"
                    >
                      MD
                    </button>
                    <button
                      onClick={() => handleExport(rep.report_id, 'csv')}
                      className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[11px] transition"
                      title="Export CSV"
                    >
                      CSV
                    </button>
                    <button
                      onClick={() => handleVerifyIntegrity(rep.report_id)}
                      className="px-2 py-1 bg-indigo-950/60 hover:bg-indigo-900/80 text-indigo-300 rounded text-[11px] transition border border-indigo-800/40"
                      title="Verify SHA-256 Integrity"
                    >
                      Verify
                    </button>
                    <button
                      onClick={() => handleDelete(rep.report_id)}
                      className="px-1.5 py-1 bg-slate-800 hover:bg-red-900/60 text-slate-400 hover:text-red-300 rounded text-[11px] transition"
                      title="Delete Report"
                    >
                      ✕
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Integrity Verification Modal/Banner */}
      {verifyResult && (
        <div className="mt-4 p-4 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono">
          <div className="flex justify-between items-center mb-2">
            <span className="font-bold flex items-center space-x-2">
              <span>{verifyResult.valid ? '✅' : '❌'}</span>
              <span className={verifyResult.valid ? 'text-emerald-400' : 'text-red-400'}>
                SHA-256 Report Integrity: {verifyResult.valid ? 'VERIFIED (IMMUTABLE)' : 'TAMPERED / FAILED'}
              </span>
            </span>
            <button onClick={() => setVerifyResult(null)} className="text-slate-400 hover:text-slate-200">✕</button>
          </div>
          <p className="text-slate-300 font-sans mb-1">{verifyResult.message}</p>
          {verifyResult.persisted_hash && (
            <p className="text-slate-500 text-[11px]">Hash: <span className="text-cyan-400">{verifyResult.persisted_hash}</span></p>
          )}
        </div>
      )}

      {/* Selected Report Drawer */}
      {selectedReport && (
        <div className="mt-6 p-5 bg-slate-950 border border-cyan-800/50 rounded-xl shadow-2xl">
          <div className="flex justify-between items-start mb-4 pb-3 border-b border-slate-800">
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-base font-bold text-slate-100">{selectedReport.title}</h3>
                <span className="text-xs bg-cyan-900/40 text-cyan-300 px-2 py-0.5 rounded border border-cyan-700/40 font-mono">
                  {selectedReport.report_id}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1">{selectedReport.description}</p>
            </div>
            <button
              onClick={() => setSelectedReport(null)}
              className="text-slate-400 hover:text-slate-200 text-sm px-2 py-1 bg-slate-800 rounded"
            >
              ✕ Close
            </button>
          </div>

          {/* Executive Summary Metrics Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5 font-mono text-xs">
            <div className="p-3 bg-slate-900 border border-slate-800 rounded">
              <span className="text-slate-400 block text-[11px]">Security Score</span>
              <span className="text-base font-bold text-emerald-400">{selectedReport.executive_summary.security_score}%</span>
            </div>
            <div className="p-3 bg-slate-900 border border-slate-800 rounded">
              <span className="text-slate-400 block text-[11px]">Posture</span>
              <span className="text-base font-bold text-cyan-400">{selectedReport.executive_summary.security_posture}</span>
            </div>
            <div className="p-3 bg-slate-900 border border-slate-800 rounded">
              <span className="text-slate-400 block text-[11px]">Total Assertions</span>
              <span className="text-base font-bold text-slate-200">{selectedReport.executive_summary.total_tests}</span>
            </div>
            <div className="p-3 bg-slate-900 border border-slate-800 rounded">
              <span className="text-slate-400 block text-[11px]">Evidence Items</span>
              <span className="text-base font-bold text-indigo-400">{selectedReport.evidence_count}</span>
            </div>
          </div>

          {/* Compliance Mappings */}
          <div className="mb-5">
            <h4 className="text-xs font-bold text-slate-300 mb-2 flex items-center justify-between">
              <span>Framework Compliance & Control Coverage</span>
              <span className="text-[10px] text-amber-400 font-sans italic">
                *Informational evidence only; does not constitute legal certification.
              </span>
            </h4>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse font-sans">
                <thead>
                  <tr className="bg-slate-900 text-slate-400 border-b border-slate-800">
                    <th className="py-2 px-2.5">Framework</th>
                    <th className="py-2 px-2.5">Control ID</th>
                    <th className="py-2 px-2.5">Control Name</th>
                    <th className="py-2 px-2.5">Mapped Gateway Controls</th>
                    <th className="py-2 px-2.5">Evidence Items</th>
                    <th className="py-2 px-2.5">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/40 font-mono text-[11px]">
                  {selectedReport.compliance_mappings?.map((cm, idx) => (
                    <tr key={idx} className="hover:bg-slate-900/60">
                      <td className="py-1.5 px-2.5 text-cyan-400">{cm.framework}</td>
                      <td className="py-1.5 px-2.5 font-bold text-slate-200">{cm.control_id}</td>
                      <td className="py-1.5 px-2.5 font-sans text-slate-300">{cm.control_name}</td>
                      <td className="py-1.5 px-2.5 font-sans text-slate-400">{cm.gateway_controls?.join(', ')}</td>
                      <td className="py-1.5 px-2.5 text-center text-slate-300">{cm.evidence_count}</td>
                      <td className="py-1.5 px-2.5 font-sans">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] ${cm.evidence_count > 0 ? 'bg-emerald-950/80 text-emerald-300' : 'bg-slate-800 text-slate-400'}`}>
                          {cm.coverage_status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Normalized Evidence Samples */}
          <div>
            <h4 className="text-xs font-bold text-slate-300 mb-2">
              Sanitized Control Evidence Records ({evidenceItems.length} items loaded)
            </h4>
            <div className="space-y-2 max-h-60 overflow-y-auto pr-1 font-mono text-xs">
              {loadingEvidence ? (
                <p className="text-slate-500 font-sans text-xs">Loading evidence items...</p>
              ) : evidenceItems.length === 0 ? (
                <p className="text-slate-500 font-sans text-xs">No evidence records associated with this report.</p>
              ) : (
                evidenceItems.map((ev) => (
                  <div key={ev.evidence_id} className="p-2.5 bg-slate-900/80 border border-slate-800 rounded">
                    <div className="flex justify-between items-center text-[11px] mb-1">
                      <span className="text-cyan-400 font-semibold">{ev.test_id} ({ev.category})</span>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${ev.status === 'PASS' ? 'bg-emerald-950 text-emerald-400' : 'bg-red-950 text-red-400'}`}>
                        {ev.status}
                      </span>
                    </div>
                    <p className="text-slate-300 font-sans text-[11px]">{ev.expected_behavior}</p>
                    <p className="text-slate-400 font-sans text-[11px] mt-0.5">{ev.actual_behavior}</p>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* Generate Report Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-md w-full shadow-2xl">
            <h3 className="text-base font-bold text-slate-100 mb-4">Generate Security Assessment Report</h3>
            <form onSubmit={handleCreateReport} className="space-y-4 text-xs font-sans">
              <div>
                <label className="block text-slate-300 mb-1 font-semibold">Report Type</label>
                <select
                  value={formData.report_type}
                  onChange={(e) => setFormData({ ...formData, report_type: e.target.value })}
                  className="w-full bg-slate-800 border border-slate-700 text-slate-200 rounded px-3 py-2 focus:outline-none focus:border-cyan-500"
                >
                  <option value="CAMPAIGN">Campaign Assessment Report</option>
                  <option value="SECURITY_VALIDATION">Security Validation Report</option>
                  <option value="EXECUTIVE">Executive Summary Report</option>
                  <option value="COMPLIANCE">Compliance & Framework Report</option>
                </select>
              </div>

              {formData.report_type === 'CAMPAIGN' && (
                <div>
                  <label className="block text-slate-300 mb-1 font-semibold">Associated Campaign</label>
                  <select
                    value={formData.campaign_id}
                    onChange={(e) => setFormData({ ...formData, campaign_id: e.target.value })}
                    className="w-full bg-slate-800 border border-slate-700 text-slate-200 rounded px-3 py-2 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="">-- Most Recent Active Campaign --</option>
                    {campaigns.map((c) => (
                      <option key={c.campaign_id} value={c.campaign_id}>
                        {c.name} ({c.campaign_id})
                      </option>
                    ))}
                  </select>
                </div>
              )}

              <div>
                <label className="block text-slate-300 mb-1 font-semibold">Report Title (Optional)</label>
                <input
                  type="text"
                  placeholder="e.g. Q3 SOC Security Validation Report"
                  value={formData.title}
                  onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                  className="w-full bg-slate-800 border border-slate-700 text-slate-200 rounded px-3 py-2 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 mb-1 font-semibold">Description / Scope (Optional)</label>
                <textarea
                  rows="2"
                  placeholder="e.g. Full adversarial test suite against gateway controls."
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  className="w-full bg-slate-800 border border-slate-700 text-slate-200 rounded px-3 py-2 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex justify-end space-x-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded font-semibold transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded font-semibold shadow transition"
                >
                  {loading ? 'Generating...' : 'Generate Report'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
