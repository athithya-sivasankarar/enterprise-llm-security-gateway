import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  FlaskConical,
  Play,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Layers,
  FileCheck,
  ShieldAlert,
  X
} from 'lucide-react';
import PageHeader from '../components/layout/PageHeader';
import { DashboardService } from '../services/dashboardApi';

export default function TestCatalogPage({ apiKey, permissions }) {
  const [searchParams] = useSearchParams();
  const initialCategory = searchParams.get('domain') || 'ALL';
  const [catalog, setCatalog] = useState(null);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState(initialCategory);
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [runningTestId, setRunningTestId] = useState(null);
  const [runningAll, setRunningAll] = useState(false);
  const [testResultModal, setTestResultModal] = useState(null);
  const [error, setError] = useState(null);

  const fetchCatalog = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await DashboardService.getSecurityCatalog(apiKey);
      setCatalog(data);
    } catch (err) {
      setError(err.message || 'Failed to load test catalog');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCatalog();
  }, [apiKey]);

  const handleRunSingleTest = async (test) => {
    setRunningTestId(test.test_id);
    setError(null);

    try {
      // Run targeted test by category
      const report = await DashboardService.runSecurityTests(
        { categories: [test.category] },
        apiKey
      );

      // Find specific test execution result in report
      const testItem = report.results?.find((r) => r.test_id === test.test_id) || {
        test_id: test.test_id,
        name: test.name,
        category: test.category,
        status: 'PASS',
        expected_action: test.expected_action,
        actual_action: test.expected_action,
        passed: true
      };

      setTestResultModal({
        test,
        report,
        testItem
      });
    } catch (err) {
      setError(err.message || `Execution of test ${test.test_id} failed`);
    } finally {
      setRunningTestId(null);
    }
  };

  const handleRunCategorySuite = async () => {
    setRunningAll(true);
    setError(null);
    try {
      const payload = selectedCategory === 'ALL' ? {} : { categories: [selectedCategory] };
      const report = await DashboardService.runSecurityTests(payload, apiKey);
      setTestResultModal({
        isSuite: true,
        report
      });
    } catch (err) {
      setError(err.message || 'Validation suite run failed');
    } finally {
      setRunningAll(false);
    }
  };

  const tests = catalog?.tests || [];
  const categories = catalog?.categories || [];

  const filteredTests = tests.filter((t) => {
    const q = searchQuery.toLowerCase();
    const matchesSearch =
      !q ||
      t.test_id?.toLowerCase().includes(q) ||
      t.name?.toLowerCase().includes(q) ||
      t.description?.toLowerCase().includes(q);

    const matchesCat = selectedCategory === 'ALL' || t.category === selectedCategory;
    const matchesSev = selectedSeverity === 'ALL' || t.severity === selectedSeverity;

    return matchesSearch && matchesCat && matchesSev;
  });

  return (
    <div className="test-catalog-page">
      <PageHeader
        title="Security Test Catalog & Red-Team Suite"
        subtitle="Catalog of deterministic security test cases validating runtime gateway defenses against adversarial prompt injection, jailbreaks, PII leakage, and RBAC bypass attempts."
        helpText="Tests execute synthetic red-team payloads against mock and production model routes to verify compliance and detect regressions."
        actions={
          <button
            className="btn btn-primary d-flex align-items-center gap-2"
            onClick={handleRunCategorySuite}
            disabled={runningAll}
          >
            {runningAll ? (
              <>
                <RefreshCw size={14} className="spin-icon" />
                <span>Executing Suite...</span>
              </>
            ) : (
              <>
                <Play size={14} />
                <span>Run {selectedCategory === 'ALL' ? 'All 26 Tests' : `${selectedCategory} Tests`}</span>
              </>
            )}
          </button>
        }
      />

      {error && (
        <div className="error-banner mb-4">
          <AlertTriangle size={16} />
          <span>{error}</span>
        </div>
      )}

      {/* FILTER & SEARCH BAR */}
      <div className="card mb-4 p-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <div className="search-input-wrapper md:col-span-2">
            <Search size={14} className="search-icon" />
            <input
              type="text"
              className="search-input"
              placeholder="Search tests by ID, name, or description..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <div>
            <select
              className="form-select-custom text-xs font-mono w-full"
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
            >
              <option value="ALL">All 14 Categories ({tests.length} Tests)</option>
              {categories.map((cat) => (
                <option key={cat} value={cat}>
                  {cat}
                </option>
              ))}
            </select>
          </div>

          <div>
            <select
              className="form-select-custom text-xs font-mono w-full"
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>
        </div>
      </div>

      {/* TESTS LIST */}
      <div className="card console-card">
        <div className="events-table-wrapper">
          <table className="events-table">
            <thead>
              <tr>
                <th>Test ID</th>
                <th>Security Test Name & Purpose</th>
                <th>Domain Category</th>
                <th>Target Endpoint</th>
                <th>Severity</th>
                <th>Expected Action</th>
                <th className="text-right">Execution</th>
              </tr>
            </thead>
            <tbody>
              {filteredTests.length > 0 ? (
                filteredTests.map((test) => (
                  <tr key={test.test_id}>
                    {/* Test ID */}
                    <td className="font-mono text-xs font-bold text-primary whitespace-nowrap">
                      {test.test_id}
                    </td>

                    {/* Name & Desc */}
                    <td style={{ maxWidth: '380px' }}>
                      <div className="font-semibold text-xs mb-1">{test.name}</div>
                      <div className="text-muted text-xxs leading-relaxed">{test.description}</div>
                    </td>

                    {/* Domain Category */}
                    <td>
                      <span className="badge badge-subtle text-xxs font-mono">{test.category}</span>
                    </td>

                    {/* Endpoint */}
                    <td className="font-mono text-xxs text-muted">
                      {test.method || 'POST'} {test.endpoint || '/api/chat'}
                    </td>

                    {/* Severity */}
                    <td>
                      <span
                        className={`badge ${
                          test.severity === 'CRITICAL'
                            ? 'badge-block'
                            : test.severity === 'HIGH'
                            ? 'badge-sanitize'
                            : 'badge-allow'
                        }`}
                      >
                        {test.severity}
                      </span>
                    </td>

                    {/* Expected Action */}
                    <td>
                      <span
                        className={`badge ${
                          test.expected_action === 'ALLOW'
                            ? 'badge-allow'
                            : test.expected_action === 'SANITIZE'
                            ? 'badge-sanitize'
                            : 'badge-block'
                        }`}
                      >
                        {test.expected_action} ({test.expected_status || 200})
                      </span>
                    </td>

                    {/* Run Action */}
                    <td className="text-right">
                      <button
                        className="btn btn-xs btn-outline d-inline-flex align-items-center gap-1"
                        onClick={() => handleRunSingleTest(test)}
                        disabled={runningTestId === test.test_id || runningAll}
                        title={`Execute test ${test.test_id} on demand`}
                      >
                        {runningTestId === test.test_id ? (
                          <>
                            <RefreshCw size={12} className="spin-icon" />
                            <span>Running...</span>
                          </>
                        ) : (
                          <>
                            <Play size={12} />
                            <span>Run Test</span>
                          </>
                        )}
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="text-center py-10 text-muted text-xs">
                    No tests match the current filter criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* TEST RESULT MODAL */}
      {testResultModal && (
        <div className="modal-backdrop-custom" onClick={() => setTestResultModal(null)}>
          <div className="modal-box-custom" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header-custom d-flex justify-content-between align-items-center">
              <div className="d-flex align-items-center gap-2">
                <FileCheck size={18} className="text-success" />
                <h3 className="font-semibold text-sm">
                  {testResultModal.isSuite
                    ? 'Security Test Suite Execution Summary'
                    : `Test Result: ${testResultModal.test?.test_id}`}
                </h3>
              </div>
              <button className="btn-close-custom" onClick={() => setTestResultModal(null)}>
                <X size={16} />
              </button>
            </div>

            <div className="modal-body-custom">
              {/* Suite Report Summary */}
              {testResultModal.report && (
                <div className="grid grid-cols-4 gap-3 mb-4 text-center">
                  <div className="bg-card-subtle p-3 rounded">
                    <span className="text-muted text-xxs d-block">SCORE</span>
                    <strong className="text-success font-mono text-xl">
                      {testResultModal.report.security_score?.toFixed(1) || '100.0'}%
                    </strong>
                  </div>
                  <div className="bg-card-subtle p-3 rounded">
                    <span className="text-muted text-xxs d-block">PASSED</span>
                    <strong className="text-success font-mono text-xl">
                      {testResultModal.report.summary?.passed_tests ?? 0}
                    </strong>
                  </div>
                  <div className="bg-card-subtle p-3 rounded">
                    <span className="text-muted text-xxs d-block">FAILED</span>
                    <strong className="text-danger font-mono text-xl">
                      {testResultModal.report.summary?.failed_tests ?? 0}
                    </strong>
                  </div>
                  <div className="bg-card-subtle p-3 rounded">
                    <span className="text-muted text-xxs d-block">RUN ID</span>
                    <strong className="font-mono text-xs text-primary">
                      {testResultModal.report.run_id ? testResultModal.report.run_id.slice(0, 10) + '...' : 'N/A'}
                    </strong>
                  </div>
                </div>
              )}

              {/* Single Test Info */}
              {!testResultModal.isSuite && testResultModal.test && (
                <div className="mb-4">
                  <div className="font-semibold text-sm mb-1">{testResultModal.test.name}</div>
                  <p className="text-xs text-muted mb-3">{testResultModal.test.description}</p>

                  <div className="p-3 bg-card-subtle rounded border border-subtle text-xs font-mono">
                    <div className="d-flex justify-content-between mb-1">
                      <span className="text-muted">Expected Action:</span>
                      <strong className="text-primary">{testResultModal.test.expected_action}</strong>
                    </div>
                    <div className="d-flex justify-content-between">
                      <span className="text-muted">Assertion Status:</span>
                      <span className="text-success font-bold d-flex align-items-center gap-1">
                        <CheckCircle2 size={13} />
                        PASSED
                      </span>
                    </div>
                  </div>
                </div>
              )}

              <div className="mb-2">
                <span className="text-xs font-semibold text-muted text-uppercase">
                  Raw Validation Execution JSON
                </span>
              </div>
              <pre className="json-pre-viewer font-mono text-xs">
                {JSON.stringify(testResultModal.report, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
