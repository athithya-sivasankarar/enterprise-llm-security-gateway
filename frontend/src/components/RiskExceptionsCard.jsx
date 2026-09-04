import React, { useState, useEffect } from 'react';
import { FileWarning, Plus, CheckCircle, XCircle, RefreshCw, AlertCircle, Clock, ShieldAlert, Lock } from 'lucide-react';
import { DashboardService } from '../services/dashboardApi';

export default function RiskExceptionsCard({ apiKey }) {
  const [exceptions, setExceptions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [selectedException, setSelectedException] = useState(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showRenewModal, setShowRenewModal] = useState(false);
  const [renewExceptionId, setRenewExceptionId] = useState(null);
  const [actionError, setActionError] = useState(null);
  const [actionSuccess, setActionSuccess] = useState(null);

  // Form states
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    risk_type: 'GENERAL',
    severity: 'HIGH',
    owner: '',
    business_justification: '',
    compensating_controls: '',
    expires_at: ''
  });

  const [renewData, setRenewData] = useState({
    new_expires_at: '',
    renewal_justification: ''
  });

  const loadExceptions = async () => {
    setLoading(true);
    setActionError(null);
    try {
      const res = await DashboardService.getRiskExceptions({
        status: statusFilter || undefined,
        severity: severityFilter || undefined,
        limit: 100
      }, apiKey);
      setExceptions(res || []);
    } catch (err) {
      setActionError(err.message || 'Failed to fetch risk exceptions');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadExceptions();
  }, [apiKey, statusFilter, severityFilter]);

  const handleCreate = async (e) => {
    e.preventDefault();
    setActionError(null);
    setActionSuccess(null);
    try {
      if (!formData.expires_at) {
        throw new Error('Expiration date is mandatory for risk exceptions');
      }
      const payload = {
        ...formData,
        expires_at: new Date(formData.expires_at).toISOString()
      };
      const created = await DashboardService.createRiskException(payload, apiKey);
      setActionSuccess(`Created risk exception ${created.exception_id}`);
      setShowCreateModal(false);
      setFormData({
        title: '',
        description: '',
        risk_type: 'GENERAL',
        severity: 'HIGH',
        owner: '',
        business_justification: '',
        compensating_controls: '',
        expires_at: ''
      });
      loadExceptions();
    } catch (err) {
      setActionError(err.message || 'Failed to create risk exception');
    }
  };

  const handleSubmitForApproval = async (exceptionId) => {
    setActionError(null);
    try {
      await DashboardService.submitRiskException(exceptionId, apiKey);
      setActionSuccess(`Submitted exception ${exceptionId} for approval`);
      loadExceptions();
    } catch (err) {
      setActionError(err.message || 'Failed to submit exception');
    }
  };

  const handleApprove = async (exceptionId) => {
    setActionError(null);
    try {
      await DashboardService.approveRiskException(exceptionId, { decision: 'APPROVE', notes: 'Approved via SOC Dashboard' }, apiKey);
      setActionSuccess(`Approved exception ${exceptionId}`);
      loadExceptions();
    } catch (err) {
      setActionError(err.message || 'Failed to approve exception');
    }
  };

  const handleReject = async (exceptionId) => {
    setActionError(null);
    try {
      await DashboardService.rejectRiskException(exceptionId, { decision: 'REJECT', notes: 'Rejected via SOC Dashboard' }, apiKey);
      setActionSuccess(`Rejected exception ${exceptionId}`);
      loadExceptions();
    } catch (err) {
      setActionError(err.message || 'Failed to reject exception');
    }
  };

  const handleRenew = async (e) => {
    e.preventDefault();
    setActionError(null);
    try {
      if (!renewData.new_expires_at) {
        throw new Error('New expiration date is mandatory for renewal');
      }
      await DashboardService.renewRiskException(renewExceptionId, {
        new_expires_at: new Date(renewData.new_expires_at).toISOString(),
        renewal_justification: renewData.renewal_justification
      }, apiKey);
      setActionSuccess(`Renewed exception ${renewExceptionId}`);
      setShowRenewModal(false);
      setRenewData({ new_expires_at: '', renewal_justification: '' });
      loadExceptions();
    } catch (err) {
      setActionError(err.message || 'Failed to renew exception');
    }
  };

  const handleRevoke = async (exceptionId) => {
    setActionError(null);
    try {
      await DashboardService.revokeRiskException(exceptionId, { reason: 'Revoked by security administrator' }, apiKey);
      setActionSuccess(`Revoked exception ${exceptionId}`);
      loadExceptions();
    } catch (err) {
      setActionError(err.message || 'Failed to revoke exception');
    }
  };

  const handleClose = async (exceptionId) => {
    setActionError(null);
    try {
      await DashboardService.closeRiskException(exceptionId, { reason: 'Remediation completed' }, apiKey);
      setActionSuccess(`Closed exception ${exceptionId}`);
      loadExceptions();
    } catch (err) {
      setActionError(err.message || 'Failed to close exception');
    }
  };

  const getStatusBadge = (st) => {
    switch (st) {
      case 'APPROVED':
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-950/60 text-emerald-400 border border-emerald-800">APPROVED</span>;
      case 'PENDING_APPROVAL':
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-950/60 text-amber-400 border border-amber-800">PENDING APPROVAL</span>;
      case 'EXPIRED':
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-950/60 text-rose-400 border border-rose-800">EXPIRED</span>;
      case 'REJECTED':
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-800 text-slate-400 border border-slate-700">REJECTED</span>;
      case 'REVOKED':
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-800 text-slate-400 border border-slate-700">REVOKED</span>;
      case 'CLOSED':
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-800 text-slate-400 border border-slate-700">CLOSED</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-800 text-slate-300 border border-slate-700">DRAFT</span>;
    }
  };

  const getSeverityBadge = (sev) => {
    switch (sev) {
      case 'CRITICAL': return <span className="text-[11px] px-1.5 py-0.5 rounded bg-rose-950 text-rose-400 font-bold border border-rose-800">CRITICAL</span>;
      case 'HIGH': return <span className="text-[11px] px-1.5 py-0.5 rounded bg-orange-950 text-orange-400 font-bold border border-orange-800">HIGH</span>;
      case 'MEDIUM': return <span className="text-[11px] px-1.5 py-0.5 rounded bg-amber-950 text-amber-400 font-bold border border-amber-800">MEDIUM</span>;
      default: return <span className="text-[11px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">LOW</span>;
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-amber-950/60 border border-amber-700/50 rounded-lg text-amber-400">
            <FileWarning className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              Risk Exceptions & Acceptance Lifecycle
            </h2>
            <p className="text-xs text-slate-400">
              Formally governed risk acceptance with mandatory expiration and owner tracking
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold rounded-lg transition"
          >
            <Plus className="w-4 h-4" />
            Request Exception
          </button>
          <button
            onClick={loadExceptions}
            disabled={loading}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded-lg transition border border-slate-700"
          >
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* Safety Notice */}
      <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg flex items-center space-x-3">
        <Lock className="w-5 h-5 text-indigo-400 flex-shrink-0" />
        <p className="text-xs text-slate-300">
          <strong className="text-indigo-300 font-semibold">Governance Invariant:</strong> Risk exception acceptance records an approved business decision but <span className="underline font-semibold text-rose-300">never disables or bypasses</span> runtime security guardrails (DLP, RBAC, Jailbreak, Rate Limiting, or Filter rules).
        </p>
      </div>

      {actionSuccess && (
        <div className="p-3 bg-emerald-950/50 border border-emerald-800 rounded-lg text-emerald-300 text-xs flex items-center gap-2">
          <CheckCircle className="w-4 h-4 text-emerald-400 flex-shrink-0" />
          <span>{actionSuccess}</span>
        </div>
      )}

      {actionError && (
        <div className="p-3 bg-rose-950/50 border border-rose-800 rounded-lg text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-rose-400 flex-shrink-0" />
          <span>{actionError}</span>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-3 py-1.5 bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg focus:outline-none focus:border-indigo-500"
        >
          <option value="">All Statuses</option>
          <option value="DRAFT">DRAFT</option>
          <option value="PENDING_APPROVAL">PENDING APPROVAL</option>
          <option value="APPROVED">APPROVED</option>
          <option value="EXPIRED">EXPIRED</option>
          <option value="REJECTED">REJECTED</option>
          <option value="REVOKED">REVOKED</option>
          <option value="CLOSED">CLOSED</option>
        </select>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="px-3 py-1.5 bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg focus:outline-none focus:border-indigo-500"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
        </select>
      </div>

      {/* Table */}
      <div className="overflow-x-auto border border-slate-800 rounded-lg">
        <table className="w-full text-left text-xs text-slate-300">
          <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 uppercase tracking-wider font-semibold">
            <tr>
              <th className="px-4 py-3">Exception ID</th>
              <th className="px-4 py-3">Title</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Owner</th>
              <th className="px-4 py-3">Expiration</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 bg-slate-900/40">
            {exceptions.length === 0 ? (
              <tr>
                <td colSpan="7" className="px-4 py-8 text-center text-slate-500">
                  No risk exceptions found matching criteria.
                </td>
              </tr>
            ) : (
              exceptions.map((exc) => (
                <tr key={exc.exception_id} className="hover:bg-slate-800/40 transition">
                  <td className="px-4 py-3 font-mono font-bold text-indigo-300">
                    {exc.exception_id}
                  </td>
                  <td className="px-4 py-3 font-medium text-slate-200 max-w-xs truncate">
                    {exc.title}
                  </td>
                  <td className="px-4 py-3">
                    {getSeverityBadge(exc.severity)}
                  </td>
                  <td className="px-4 py-3">
                    {getStatusBadge(exc.status)}
                    {exc.is_overdue && (
                      <span className="ml-1.5 text-[10px] px-1 py-0.5 rounded bg-rose-950 text-rose-300 font-bold">
                        OVERDUE
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-slate-400 font-mono">
                    {exc.owner}
                  </td>
                  <td className="px-4 py-3 text-slate-400 font-mono text-[11px]">
                    {new Date(exc.expires_at).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-3 text-right space-x-1.5 whitespace-nowrap">
                    {exc.status === 'DRAFT' && (
                      <button
                        onClick={() => handleSubmitForApproval(exc.exception_id)}
                        className="px-2 py-1 bg-indigo-900/60 hover:bg-indigo-800 text-indigo-300 border border-indigo-700 rounded text-[11px] font-medium"
                      >
                        Submit
                      </button>
                    )}
                    {exc.status === 'PENDING_APPROVAL' && (
                      <>
                        <button
                          onClick={() => handleApprove(exc.exception_id)}
                          className="px-2 py-1 bg-emerald-900/60 hover:bg-emerald-800 text-emerald-300 border border-emerald-700 rounded text-[11px] font-medium"
                        >
                          Approve
                        </button>
                        <button
                          onClick={() => handleReject(exc.exception_id)}
                          className="px-2 py-1 bg-rose-900/60 hover:bg-rose-800 text-rose-300 border border-rose-700 rounded text-[11px] font-medium"
                        >
                          Reject
                        </button>
                      </>
                    )}
                    {(exc.status === 'APPROVED' || exc.status === 'EXPIRED') && (
                      <button
                        onClick={() => {
                          setRenewExceptionId(exc.exception_id);
                          setShowRenewModal(true);
                        }}
                        className="px-2 py-1 bg-amber-900/60 hover:bg-amber-800 text-amber-300 border border-amber-700 rounded text-[11px] font-medium"
                      >
                        Renew
                      </button>
                    )}
                    {exc.status === 'APPROVED' && (
                      <button
                        onClick={() => handleRevoke(exc.exception_id)}
                        className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded text-[11px] font-medium"
                      >
                        Revoke
                      </button>
                    )}
                    {(exc.status === 'APPROVED' || exc.status === 'PENDING_APPROVAL') && (
                      <button
                        onClick={() => handleClose(exc.exception_id)}
                        className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded text-[11px] font-medium"
                      >
                        Close
                      </button>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-lg font-bold text-slate-100">Request Security Risk Exception</h3>
            <form onSubmit={handleCreate} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Title *</label>
                <input
                  type="text"
                  required
                  value={formData.title}
                  onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                  placeholder="e.g. Temporary DLP bypass exception for test dataset"
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 text-slate-200 rounded-lg focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Description *</label>
                <textarea
                  required
                  rows="2"
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder="Detailed description of risk condition"
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 text-slate-200 rounded-lg focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1 font-semibold">Severity *</label>
                  <select
                    value={formData.severity}
                    onChange={(e) => setFormData({ ...formData, severity: e.target.value })}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 text-slate-200 rounded-lg focus:outline-none focus:border-indigo-500"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1 font-semibold">Risk Owner *</label>
                  <input
                    type="text"
                    required
                    value={formData.owner}
                    onChange={(e) => setFormData({ ...formData, owner: e.target.value })}
                    placeholder="e.g. data-platform-team"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 text-slate-200 rounded-lg focus:outline-none focus:border-indigo-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Business Justification *</label>
                <textarea
                  required
                  rows="2"
                  value={formData.business_justification}
                  onChange={(e) => setFormData({ ...formData, business_justification: e.target.value })}
                  placeholder="Documented reason why the risk is temporarily accepted"
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 text-slate-200 rounded-lg focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Compensating Controls</label>
                <input
                  type="text"
                  value={formData.compensating_controls}
                  onChange={(e) => setFormData({ ...formData, compensating_controls: e.target.value })}
                  placeholder="e.g. Network isolation, synthetic data scrubbing, enhanced logging"
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 text-slate-200 rounded-lg focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Mandatory Expiration Date *</label>
                <input
                  type="datetime-local"
                  required
                  value={formData.expires_at}
                  onChange={(e) => setFormData({ ...formData, expires_at: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 text-slate-200 rounded-lg focus:outline-none focus:border-indigo-500 font-mono"
                />
                <p className="text-[10px] text-amber-400 mt-1">
                  Permanent exceptions are strictly forbidden.
                </p>
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-lg"
                >
                  Create Exception
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Renew Modal */}
      {showRenewModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-lg font-bold text-slate-100">Renew Risk Exception ({renewExceptionId})</h3>
            <form onSubmit={handleRenew} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1 font-semibold">New Expiration Date *</label>
                <input
                  type="datetime-local"
                  required
                  value={renewData.new_expires_at}
                  onChange={(e) => setRenewData({ ...renewData, new_expires_at: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 text-slate-200 rounded-lg focus:outline-none focus:border-indigo-500 font-mono"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Renewal Justification *</label>
                <textarea
                  required
                  rows="3"
                  value={renewData.renewal_justification}
                  onChange={(e) => setRenewData({ ...renewData, renewal_justification: e.target.value })}
                  placeholder="Justification for extending accepted risk window"
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 text-slate-200 rounded-lg focus:outline-none focus:border-indigo-500"
                />
              </div>
              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowRenewModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white font-semibold rounded-lg"
                >
                  Confirm Renewal
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
