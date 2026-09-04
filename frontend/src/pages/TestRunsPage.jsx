import React, { useState, useEffect } from 'react';
import {
  ListOrdered,
  RefreshCw,
  Search,
  FileCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Eye,
  X,
  Clock,
  Layers
} from 'lucide-react';
import PageHeader from '../components/layout/PageHeader';
import Pagination from '../components/layout/Pagination';
import { DashboardService } from '../services/dashboardApi';

export default function TestRunsPage({ apiKey, permissions }) {
  const [runs, setRuns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedRunReport, setSelectedRunReport] = useState(null);
  const [loadingReport, setLoadingReport] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const fetchRuns = async () => {
    try {
      setLoading(true);
      const data = await DashboardService.getSecurityTestRuns(apiKey);
      setRuns(data || []);
    } catch (err) {
      console.error('Failed to load test runs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRuns();
  }, [apiKey]);

  const handleViewReport = async (runId) => {
    try {
      setLoadingReport(true);
      const report = await DashboardService.getSecurityTestReport(runId, apiKey);
      setSelectedRunReport(report);
    } catch (err) {
      console.error('Failed loading report for run:', runId, err);
    } finally {
      setLoadingReport(false);
    }
  };

  const filteredRuns = runs.filter((r) => {
    const q = searchQuery.toLowerCase();
    return (
      !q ||
      r.run_id?.toLowerCase().includes(q) ||
      r.status?.toLowerCase().includes(q) ||
      r.policy_version?.toLowerCase().includes(q)
    );
  });

  const paginatedRuns = filteredRuns.slice(
    (currentPage - 1) * pageSize,
    currentPage * pageSize
  );

  return (
    <div className="test-runs-page">
      <PageHeader
        title="Security Test Runs & Execution History"
        subtitle="Chronological execution logs and audit reports of all automated red-team test suites and campaign validation runs."
        helpText="Inspect per-run assertions, pass/fail metrics, execution latencies, and generated findings."
        actions={
          <button className="btn btn-outline" onClick={fetchRuns} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'spin-icon' : ''} />
            <span>Refresh Runs</span>
          </button>
        }
      />

      {/* FILTER & SEARCH */}
      <div className="card mb-4 p-4">
        <div className="search-input-wrapper max-w-md">
          <Search size={14} className="search-icon" />
          <input
            type="text"
            className="search-input"
            placeholder="Search runs by Run ID, status, or policy..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setCurrentPage(1);
            }}
          />
        </div>
      </div>

      {/* RUNS TABLE */}
      <div className="card console-card">
        <div className="events-table-wrapper">
          <table className="events-table">
            <thead>
              <tr>
                <th>Run ID</th>
                <th>Executed At</th>
                <th>Status</th>
                <th>Security Score</th>
                <th>Passed Assertions</th>
                <th>Failed Assertions</th>
                <th>Policy Version</th>
                <th className="text-right">Report</th>
              </tr>
            </thead>
            <tbody>
              {paginatedRuns.length > 0 ? (
                paginatedRuns.map((r) => {
                  const score = r.security_score ?? 100;
                  const isCompleted = r.status === 'COMPLETED';

                  return (
                    <tr key={r.run_id}>
                      {/* Run ID */}
                      <td className="font-mono text-xs font-bold text-primary whitespace-nowrap">
                        {r.run_id}
                      </td>

                      {/* Timestamp */}
                      <td className="font-mono text-xxs text-muted">
                        {r.started_at ? new Date(r.started_at).toLocaleString() : 'N/A'}
                      </td>

                      {/* Status */}
                      <td>
                        <span className={`badge ${isCompleted ? 'badge-allow' : 'badge-sanitize'}`}>
                          {r.status || 'COMPLETED'}
                        </span>
                      </td>

                      {/* Score */}
                      <td>
                        <span className={`font-mono text-xs font-bold ${score >= 90 ? 'text-success' : score >= 70 ? 'text-warning' : 'text-danger'}`}>
                          {score.toFixed(1)}%
                        </span>
                      </td>

                      {/* Passed */}
                      <td>
                        <div className="d-flex align-items-center gap-1 text-success font-mono text-xs">
                          <CheckCircle2 size={13} />
                          <span>{r.passed_tests ?? r.summary?.passed_tests ?? 0}</span>
                        </div>
                      </td>

                      {/* Failed */}
                      <td>
                        <div className="d-flex align-items-center gap-1 font-mono text-xs">
                          {r.failed_tests > 0 ? (
                            <span className="text-danger font-bold d-flex align-items-center gap-1">
                              <XCircle size={13} />
                              {r.failed_tests}
                            </span>
                          ) : (
                            <span className="text-muted">0</span>
                          )}
                        </div>
                      </td>

                      {/* Policy Version */}
                      <td className="font-mono text-xxs text-muted">
                        v{r.policy_version || '1.0.0'}
                      </td>

                      {/* View Report */}
                      <td className="text-right">
                        <button
                          className="btn btn-xs btn-outline d-inline-flex align-items-center gap-1"
                          onClick={() => handleViewReport(r.run_id)}
                          title="Inspect detailed test run report"
                        >
                          <Eye size={12} />
                          <span>Report</span>
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={8} className="text-center py-10 text-muted text-xs">
                    No test runs found. Execute a test suite from the Test Catalog.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <Pagination
          currentPage={currentPage}
          totalItems={filteredRuns.length}
          pageSize={pageSize}
          onPageChange={setCurrentPage}
          onPageSizeChange={setPageSize}
        />
      </div>

      {/* REPORT INSPECTOR MODAL */}
      {selectedRunReport && (
        <div className="modal-backdrop-custom" onClick={() => setSelectedRunReport(null)}>
          <div className="modal-box-custom" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header-custom d-flex justify-content-between align-items-center">
              <div className="d-flex align-items-center gap-2">
                <FileCheck size={18} className="text-cyan" />
                <h3 className="font-semibold text-sm">Security Test Run Report: {selectedRunReport.run_id}</h3>
              </div>
              <button className="btn-close-custom" onClick={() => setSelectedRunReport(null)}>
                <X size={16} />
              </button>
            </div>

            <div className="modal-body-custom">
              <div className="grid grid-cols-4 gap-3 mb-4 text-center">
                <div className="bg-card-subtle p-3 rounded">
                  <span className="text-muted text-xxs d-block">SCORE</span>
                  <strong className="text-success font-mono text-xl">
                    {selectedRunReport.security_score?.toFixed(1) || 100}%
                  </strong>
                </div>
                <div className="bg-card-subtle p-3 rounded">
                  <span className="text-muted text-xxs d-block">PASSED</span>
                  <strong className="text-success font-mono text-xl">
                    {selectedRunReport.summary?.passed_tests ?? 0}
                  </strong>
                </div>
                <div className="bg-card-subtle p-3 rounded">
                  <span className="text-muted text-xxs d-block">FAILED</span>
                  <strong className="text-danger font-mono text-xl">
                    {selectedRunReport.summary?.failed_tests ?? 0}
                  </strong>
                </div>
                <div className="bg-card-subtle p-3 rounded">
                  <span className="text-muted text-xxs d-block">POLICY</span>
                  <strong className="font-mono text-sm text-primary">
                    v{selectedRunReport.policy_version || '1.0.0'}
                  </strong>
                </div>
              </div>

              {/* Category Breakdown */}
              {selectedRunReport.category_summaries && (
                <div className="mb-4">
                  <div className="text-xs font-semibold text-muted text-uppercase mb-2">Category Results</div>
                  <div className="grid grid-cols-2 gap-2">
                    {selectedRunReport.category_summaries.map((cat, idx) => (
                      <div key={idx} className="d-flex justify-content-between p-2 bg-card-subtle rounded text-xs font-mono">
                        <span>{cat.category}</span>
                        <span className={cat.pass_rate === 100 ? 'text-success' : 'text-warning'}>
                          {cat.passed}/{cat.total} ({cat.pass_rate.toFixed(0)}%)
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="mb-2">
                <span className="text-xs font-semibold text-muted text-uppercase">Full Report Telemetry</span>
              </div>
              <pre className="json-pre-viewer font-mono text-xs">
                {JSON.stringify(selectedRunReport, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
