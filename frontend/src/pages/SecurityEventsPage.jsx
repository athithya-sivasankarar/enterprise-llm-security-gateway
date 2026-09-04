import React, { useState, useEffect } from 'react';
import {
  History,
  Search,
  Filter,
  RefreshCw,
  Eye,
  X,
  Lock,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  FileCode,
  Calendar,
  Layers
} from 'lucide-react';
import PageHeader from '../components/layout/PageHeader';
import Pagination from '../components/layout/Pagination';
import { DashboardService } from '../services/dashboardApi';

export default function SecurityEventsPage({ apiKey }) {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [threatFilter, setThreatFilter] = useState('ALL');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [modelFilter, setModelFilter] = useState('ALL');
  const [selectedEvent, setSelectedEvent] = useState(null);

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const fetchEvents = async () => {
    try {
      setLoading(true);
      const res = await DashboardService.getSecurityEvents(apiKey, 100);
      setEvents(res?.events || []);
    } catch (err) {
      console.error('Failed to load security events:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [apiKey]);

  // Unique lists for filter dropdowns
  const uniqueModels = Array.from(new Set(events.map((e) => e.model).filter(Boolean)));
  const uniqueThreats = Array.from(new Set(events.map((e) => e.threat_type).filter(Boolean)));

  // Filter events
  const filteredEvents = events.filter((e) => {
    const q = searchQuery.toLowerCase();
    const matchesSearch =
      !q ||
      e.request_id?.toLowerCase().includes(q) ||
      e.user?.toLowerCase().includes(q) ||
      e.role?.toLowerCase().includes(q) ||
      e.model?.toLowerCase().includes(q) ||
      e.threat_type?.toLowerCase().includes(q);

    const matchesAction = actionFilter === 'ALL' || e.action === actionFilter;
    const matchesThreat = threatFilter === 'ALL' || e.threat_type === threatFilter;
    const matchesModel = modelFilter === 'ALL' || e.model === modelFilter;

    let matchesRisk = true;
    if (riskFilter === 'CRITICAL') matchesRisk = e.risk_score >= 80;
    else if (riskFilter === 'HIGH') matchesRisk = e.risk_score >= 60 && e.risk_score < 80;
    else if (riskFilter === 'MEDIUM') matchesRisk = e.risk_score >= 30 && e.risk_score < 60;
    else if (riskFilter === 'LOW') matchesRisk = e.risk_score < 30;

    return matchesSearch && matchesAction && matchesThreat && matchesModel && matchesRisk;
  });

  // Paginated slice
  const paginatedEvents = filteredEvents.slice(
    (currentPage - 1) * pageSize,
    currentPage * pageSize
  );

  return (
    <div className="security-events-page">
      <PageHeader
        title="Security Audit & Event Log"
        subtitle="Immutable, metadata-only security audit trail recording all runtime LLM requests, rate limits, PII sanitizations, and blocked adversarial threats."
        helpText="Strict privacy standard: Gateway logs contain sanitized metadata, latency metrics, and threat scores only. Raw prompts and keys are never stored."
        actions={
          <button className="btn btn-outline" onClick={fetchEvents} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'spin-icon' : ''} />
            <span>Refresh Events</span>
          </button>
        }
      />

      {/* FILTER & SEARCH BAR */}
      <div className="card mb-4 p-4">
        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          {/* Search */}
          <div className="search-input-wrapper md:col-span-2">
            <Search size={14} className="search-icon" />
            <input
              type="text"
              className="search-input"
              placeholder="Search by Request ID, user, role, model, threat..."
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setCurrentPage(1);
              }}
            />
          </div>

          {/* Action Filter */}
          <div>
            <select
              className="form-select-custom text-xs font-mono w-full"
              value={actionFilter}
              onChange={(e) => {
                setActionFilter(e.target.value);
                setCurrentPage(1);
              }}
            >
              <option value="ALL">All Actions</option>
              <option value="ALLOW">ALLOW (Benign)</option>
              <option value="SANITIZE">SANITIZE (PII Scrubbed)</option>
              <option value="BLOCK">BLOCK (Violation)</option>
            </select>
          </div>

          {/* Threat Type Filter */}
          <div>
            <select
              className="form-select-custom text-xs font-mono w-full"
              value={threatFilter}
              onChange={(e) => {
                setThreatFilter(e.target.value);
                setCurrentPage(1);
              }}
            >
              <option value="ALL">All Threat Types</option>
              {uniqueThreats.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>

          {/* Risk Level Filter */}
          <div>
            <select
              className="form-select-custom text-xs font-mono w-full"
              value={riskFilter}
              onChange={(e) => {
                setRiskFilter(e.target.value);
                setCurrentPage(1);
              }}
            >
              <option value="ALL">All Risk Scores</option>
              <option value="CRITICAL">Critical (80 - 100)</option>
              <option value="HIGH">High (60 - 79)</option>
              <option value="MEDIUM">Medium (30 - 59)</option>
              <option value="LOW">Low (0 - 29)</option>
            </select>
          </div>
        </div>
      </div>

      {/* EVENTS TABLE */}
      <div className="card console-card">
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
                <th>Threat Classification</th>
                <th>PII Scrubbing</th>
                <th>Status</th>
                <th>Latency</th>
                <th className="text-right">Details</th>
              </tr>
            </thead>
            <tbody>
              {paginatedEvents.length > 0 ? (
                paginatedEvents.map((evt) => (
                  <tr key={evt.request_id || evt.timestamp}>
                    {/* Timestamp */}
                    <td className="font-mono text-xxs text-muted whitespace-nowrap">
                      {evt.timestamp ? new Date(evt.timestamp).toLocaleString() : 'N/A'}
                    </td>

                    {/* Request ID */}
                    <td className="font-mono text-xs text-primary font-medium">
                      {evt.request_id ? `${evt.request_id.slice(0, 10)}...` : 'N/A'}
                    </td>

                    {/* User / Role */}
                    <td>
                      <div className="font-semibold text-xs">{evt.user || 'developer'}</div>
                      <div className="font-mono text-xxs text-muted">{evt.role || 'admin'}</div>
                    </td>

                    {/* Model */}
                    <td className="font-mono text-xs">{evt.model || 'mock-model'}</td>

                    {/* Action */}
                    <td>
                      <span
                        className={`badge ${
                          evt.action === 'ALLOW'
                            ? 'badge-allow'
                            : evt.action === 'SANITIZE'
                            ? 'badge-sanitize'
                            : 'badge-block'
                        }`}
                      >
                        {evt.action}
                      </span>
                    </td>

                    {/* Risk Score */}
                    <td>
                      <span
                        className={`font-mono text-xs font-bold ${
                          evt.risk_score >= 80
                            ? 'text-danger'
                            : evt.risk_score >= 50
                            ? 'text-warning'
                            : 'text-success'
                        }`}
                      >
                        {evt.risk_score}/100
                      </span>
                    </td>

                    {/* Threat Type */}
                    <td>
                      {evt.threat_type ? (
                        <span className="badge badge-threat text-xxs font-mono">
                          {evt.threat_type}
                        </span>
                      ) : (
                        <span className="text-muted text-xs">—</span>
                      )}
                    </td>

                    {/* PII Scrubbing */}
                    <td>
                      {evt.pii_detected ? (
                        <span className="badge badge-sanitize text-xxs">PII DETECTED</span>
                      ) : (
                        <span className="text-muted text-xs">Clean</span>
                      )}
                    </td>

                    {/* HTTP Status */}
                    <td className="font-mono text-xs">
                      <span className={evt.response_status === 200 ? 'text-success' : 'text-danger'}>
                        {evt.response_status || 200}
                      </span>
                    </td>

                    {/* Latency */}
                    <td className="font-mono text-xs">{evt.latency_ms ? `${evt.latency_ms}ms` : '—'}</td>

                    {/* Action: Inspect Modal */}
                    <td className="text-right">
                      <button
                        className="btn btn-xs btn-ghost"
                        onClick={() => setSelectedEvent(evt)}
                        title="View audit metadata details"
                      >
                        <Eye size={13} />
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={11} className="text-center py-10 text-muted text-xs">
                    No security events found matching the criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* PAGINATION */}
        <Pagination
          currentPage={currentPage}
          totalItems={filteredEvents.length}
          pageSize={pageSize}
          onPageChange={setCurrentPage}
          onPageSizeChange={setPageSize}
        />
      </div>

      {/* EVENT DETAIL INSPECTOR MODAL */}
      {selectedEvent && (
        <div className="modal-backdrop-custom" onClick={() => setSelectedEvent(null)}>
          <div className="modal-box-custom" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header-custom d-flex justify-content-between align-items-center">
              <div className="d-flex align-items-center gap-2">
                <FileCode size={18} className="text-cyan" />
                <h3 className="font-semibold text-sm">Security Audit Record Inspector</h3>
              </div>
              <button className="btn-close-custom" onClick={() => setSelectedEvent(null)}>
                <X size={16} />
              </button>
            </div>

            <div className="modal-body-custom">
              <div className="grid grid-cols-2 gap-3 mb-4 text-xs font-mono">
                <div className="bg-card-subtle p-3 rounded">
                  <span className="text-muted text-xxs d-block">REQUEST ID</span>
                  <strong>{selectedEvent.request_id}</strong>
                </div>
                <div className="bg-card-subtle p-3 rounded">
                  <span className="text-muted text-xxs d-block">TIMESTAMP</span>
                  <strong>{selectedEvent.timestamp ? new Date(selectedEvent.timestamp).toISOString() : 'N/A'}</strong>
                </div>
                <div className="bg-card-subtle p-3 rounded">
                  <span className="text-muted text-xxs d-block">USER & ROLE</span>
                  <strong>{selectedEvent.user} ({selectedEvent.role})</strong>
                </div>
                <div className="bg-card-subtle p-3 rounded">
                  <span className="text-muted text-xxs d-block">TARGET MODEL</span>
                  <strong>{selectedEvent.model}</strong>
                </div>
              </div>

              <div className="mb-2">
                <span className="text-xs font-semibold text-muted text-uppercase">
                  Complete Sanitized Audit JSON
                </span>
              </div>
              <pre className="json-pre-viewer font-mono text-xs">
                {JSON.stringify(selectedEvent, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
