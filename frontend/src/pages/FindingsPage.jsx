import React, { useState, useEffect } from 'react';
import {
  AlertOctagon,
  Search,
  Filter,
  RefreshCw,
  Eye,
  ShieldAlert,
  X,
  CheckCircle2,
  AlertTriangle,
  FileCode
} from 'lucide-react';
import PageHeader from '../components/layout/PageHeader';
import Pagination from '../components/layout/Pagination';
import { DashboardService } from '../services/dashboardApi';

export default function FindingsPage({ apiKey, permissions, onNavigate }) {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const fetchFindings = async () => {
    try {
      setLoading(true);
      const data = await DashboardService.getSecurityFindings(apiKey);
      setFindings(data || []);
    } catch (err) {
      console.error('Failed to load findings:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, [apiKey]);

  const uniqueCategories = Array.from(new Set(findings.map((f) => f.category).filter(Boolean)));

  const filteredFindings = findings.filter((f) => {
    const q = searchQuery.toLowerCase();
    const matchesSearch =
      !q ||
      f.finding_id?.toLowerCase().includes(q) ||
      f.test_id?.toLowerCase().includes(q) ||
      f.title?.toLowerCase().includes(q) ||
      f.description?.toLowerCase().includes(q);

    const matchesSev = severityFilter === 'ALL' || f.severity === severityFilter;
    const matchesCat = categoryFilter === 'ALL' || f.category === categoryFilter;

    return matchesSearch && matchesSev && matchesCat;
  });

  const paginatedFindings = filteredFindings.slice(
    (currentPage - 1) * pageSize,
    currentPage * pageSize
  );

  return (
    <div className="findings-page">
      <PageHeader
        title="Security Weaknesses & Findings"
        subtitle="Vulnerabilities, policy exceptions, and control gaps identified across automated security test runs."
        helpText="Findings are security weaknesses discovered by testing. Unlike SOC alerts which require operational triage, findings represent systematic defect tracking for developers and security engineers."
        actions={
          <button className="btn btn-outline" onClick={fetchFindings} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'spin-icon' : ''} />
            <span>Refresh Findings</span>
          </button>
        }
      />

      {/* FILTER & SEARCH */}
      <div className="card mb-4 p-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <div className="search-input-wrapper md:col-span-2">
            <Search size={14} className="search-icon" />
            <input
              type="text"
              className="search-input"
              placeholder="Search findings by ID, test ID, title, or evidence..."
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setCurrentPage(1);
              }}
            />
          </div>

          <div>
            <select
              className="form-select-custom text-xs font-mono w-full"
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setCurrentPage(1);
              }}
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          <div>
            <select
              className="form-select-custom text-xs font-mono w-full"
              value={categoryFilter}
              onChange={(e) => {
                setCategoryFilter(e.target.value);
                setCurrentPage(1);
              }}
            >
              <option value="ALL">All Control Domains</option>
              {uniqueCategories.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* FINDINGS TABLE */}
      <div className="card console-card">
        <div className="events-table-wrapper">
          <table className="events-table">
            <thead>
              <tr>
                <th>Finding Title & ID</th>
                <th>Severity</th>
                <th>Control Domain</th>
                <th>Test ID</th>
                <th>Evidence Summary</th>
                <th>Policy Version</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {paginatedFindings.length > 0 ? (
                paginatedFindings.map((f) => (
                  <tr key={f.finding_id || f.test_id}>
                    {/* Title */}
                    <td style={{ maxWidth: '320px' }}>
                      <div className="font-semibold text-xs text-primary mb-1">{f.title}</div>
                      <div className="font-mono text-xxs text-muted">{f.finding_id}</div>
                    </td>

                    {/* Severity */}
                    <td>
                      <span
                        className={`badge ${
                          f.severity === 'CRITICAL'
                            ? 'badge-block'
                            : f.severity === 'HIGH'
                            ? 'badge-sanitize'
                            : 'badge-allow'
                        }`}
                      >
                        {f.severity}
                      </span>
                    </td>

                    {/* Domain */}
                    <td>
                      <span className="badge badge-subtle text-xxs font-mono">{f.category}</span>
                    </td>

                    {/* Test ID */}
                    <td className="font-mono text-xs font-semibold">{f.test_id}</td>

                    {/* Evidence */}
                    <td style={{ maxWidth: '280px' }} className="text-xxs text-muted">
                      <div><strong className="text-success">Expected:</strong> {f.expected_behavior || 'BLOCK / SANITIZE'}</div>
                      <div><strong className="text-danger">Actual:</strong> {f.actual_behavior || 'Validation deviation'}</div>
                    </td>

                    {/* Policy */}
                    <td className="font-mono text-xxs text-muted">v{f.policy_version || '1.0.0'}</td>

                    {/* Action */}
                    <td className="text-right">
                      <button
                        className="btn btn-xs btn-outline d-inline-flex align-items-center gap-1"
                        onClick={() => setSelectedFinding(f)}
                        title="View finding evidence details"
                      >
                        <Eye size={12} />
                        <span>Evidence</span>
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="text-center py-10 text-muted text-xs">
                    No security findings matching criteria. All tested security controls are passing.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <Pagination
          currentPage={currentPage}
          totalItems={filteredFindings.length}
          pageSize={pageSize}
          onPageChange={setCurrentPage}
          onPageSizeChange={setPageSize}
        />
      </div>

      {/* FINDING EVIDENCE MODAL */}
      {selectedFinding && (
        <div className="modal-backdrop-custom" onClick={() => setSelectedFinding(null)}>
          <div className="modal-box-custom" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header-custom d-flex justify-content-between align-items-center">
              <div className="d-flex align-items-center gap-2">
                <ShieldAlert size={18} className="text-danger" />
                <h3 className="font-semibold text-sm">Finding Details: {selectedFinding.test_id}</h3>
              </div>
              <button className="btn-close-custom" onClick={() => setSelectedFinding(null)}>
                <X size={16} />
              </button>
            </div>

            <div className="modal-body-custom">
              <div className="mb-3">
                <div className="font-semibold text-base text-primary mb-1">{selectedFinding.title}</div>
                <p className="text-xs text-muted leading-relaxed">{selectedFinding.description}</p>
              </div>

              <div className="bg-card-subtle p-3 rounded border border-subtle mb-4 text-xs font-mono">
                <div className="d-flex justify-content-between mb-2">
                  <span className="text-muted">Security Control Domain:</span>
                  <strong>{selectedFinding.category}</strong>
                </div>
                <div className="d-flex justify-content-between mb-2">
                  <span className="text-muted">Severity Classification:</span>
                  <span className="badge badge-block">{selectedFinding.severity}</span>
                </div>
                <div className="d-flex justify-content-between mb-2">
                  <span className="text-muted">Target Endpoint:</span>
                  <span>{selectedFinding.endpoint || '/api/chat'}</span>
                </div>
                <div className="d-flex justify-content-between">
                  <span className="text-muted">Enforced Policy Version:</span>
                  <span>v{selectedFinding.policy_version || '1.0.0'}</span>
                </div>
              </div>

              <div className="mb-2">
                <span className="text-xs font-semibold text-muted text-uppercase">Diagnostic Evidence</span>
              </div>
              <div className="bg-card p-3 rounded border border-subtle mb-4 text-xs font-mono">
                <div className="mb-2 text-success">
                  <strong>Expected Behavior:</strong> {selectedFinding.expected_behavior}
                </div>
                <div className="text-danger">
                  <strong>Actual Behavior:</strong> {selectedFinding.actual_behavior}
                </div>
              </div>

              <pre className="json-pre-viewer font-mono text-xs">
                {JSON.stringify(selectedFinding, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
