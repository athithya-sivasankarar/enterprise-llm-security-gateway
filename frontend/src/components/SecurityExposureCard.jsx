import React, { useState, useEffect } from 'react';
import { dashboardApi } from '../services/dashboardApi';

export default function SecurityExposureCard({ apiKey }) {
  const [summary, setSummary] = useState(null);
  const [exposures, setExposures] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [statusFilter, setStatusFilter] = useState('OPEN');
  const [selectedExp, setSelectedExp] = useState(null);
  const [resolveReason, setResolveReason] = useState('');
  const [resolving, setResolving] = useState(false);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [sumData, expList] = await Promise.all([
        dashboardApi.getExposureSummary(apiKey),
        dashboardApi.getExposures(statusFilter ? { status: statusFilter } : {}, apiKey)
      ]);
      setSummary(sumData);
      setExposures(expList);
    } catch (err) {
      setError(err.message || 'Failed to load enterprise exposures');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [apiKey, statusFilter]);

  const handleResolve = async () => {
    if (!selectedExp) return;
    try {
      setResolving(true);
      await dashboardApi.resolveExposure(selectedExp.exposure_id, resolveReason || 'Mitigated via security policy update', apiKey);
      setSelectedExp(null);
      setResolveReason('');
      await loadData();
    } catch (e) {
      alert(`Resolution failed: ${e.message}`);
    } finally {
      setResolving(false);
    }
  };

  const getRiskClassBadge = (cls) => {
    const c = (cls || '').toUpperCase();
    if (c === 'CRITICAL') return 'badge badge-error font-bold';
    if (c === 'HIGH') return 'badge badge-warning font-bold';
    if (c === 'MEDIUM') return 'badge badge-info font-bold';
    return 'badge badge-success font-bold';
  };

  return (
    <div className="card shadow-lg bg-base-100 border border-base-200 p-5 rounded-2xl mb-6">
      <div className="flex flex-wrap justify-between items-center mb-4 gap-2">
        <div>
          <h2 className="text-xl font-bold flex items-center gap-2">
            <span>⚡</span> Enterprise Exposure & Attack Surface Risk
          </h2>
          <p className="text-xs text-base-content/70">
            Deterministic enterprise risk scoring (0–100) combining base severity, asset criticality, active regressions, incidents, and control coverage gaps.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select
            className="select select-sm select-bordered text-xs"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="OPEN">Open Exposures</option>
            <option value="RESOLVED">Resolved Exposures</option>
            <option value="">All Exposures</option>
          </select>
          <button onClick={loadData} className="btn btn-sm btn-ghost" title="Refresh">
            🔄
          </button>
        </div>
      </div>

      {error && (
        <div className="alert alert-error text-sm py-2 mb-4">
          <span>{error}</span>
        </div>
      )}

      {/* Summary KPI Counters */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-5">
          <div className="bg-base-200/50 p-3 rounded-xl border border-base-300">
            <div className="text-xs text-base-content/70">Enterprise Risk Score</div>
            <div className="flex items-center gap-2 mt-1">
              <span className="text-2xl font-black text-primary">{summary.enterprise_risk_score} / 100</span>
              <span className={getRiskClassBadge(summary.risk_classification)}>{summary.risk_classification}</span>
            </div>
          </div>
          <div className="bg-base-200/50 p-3 rounded-xl border border-base-300">
            <div className="text-xs text-base-content/70">Open Exposures</div>
            <div className="text-2xl font-black text-warning">{summary.open_exposures}</div>
          </div>
          <div className="bg-base-200/50 p-3 rounded-xl border border-base-300">
            <div className="text-xs text-base-content/70">Critical Severity</div>
            <div className="text-2xl font-black text-error">{summary.critical_exposures}</div>
          </div>
          <div className="bg-base-200/50 p-3 rounded-xl border border-base-300">
            <div className="text-xs text-base-content/70">High Severity</div>
            <div className="text-2xl font-black text-warning">{summary.high_exposures}</div>
          </div>
          <div className="bg-base-200/50 p-3 rounded-xl border border-base-300">
            <div className="text-xs text-base-content/70">Resolved</div>
            <div className="text-2xl font-black text-success">{summary.resolved_exposures}</div>
          </div>
        </div>
      )}

      {/* Exposures Table */}
      <div className="overflow-x-auto">
        <table className="table table-zebra table-compact w-full text-xs">
          <thead>
            <tr>
              <th>Exposure ID</th>
              <th>Category</th>
              <th>Severity</th>
              <th>Risk Score</th>
              <th>Type</th>
              <th>Asset ID</th>
              <th>Description</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="9" className="text-center py-4">Loading security exposures...</td>
              </tr>
            ) : exposures.length === 0 ? (
              <tr>
                <td colSpan="9" className="text-center py-4 text-base-content/50">No security exposures found.</td>
              </tr>
            ) : (
              exposures.map((exp) => (
                <tr key={exp.exposure_id} className="hover">
                  <td className="font-mono font-semibold">{exp.exposure_id}</td>
                  <td><span className="badge badge-xs badge-ghost">{exp.category}</span></td>
                  <td>
                    <span className={`badge badge-xs ${exp.severity === 'CRITICAL' ? 'badge-error' : exp.severity === 'HIGH' ? 'badge-warning' : 'badge-info'}`}>
                      {exp.severity}
                    </span>
                  </td>
                  <td>
                    <span className={`font-mono font-bold ${exp.risk_score >= 80 ? 'text-error' : exp.risk_score >= 60 ? 'text-warning' : 'text-success'}`}>
                      {exp.risk_score}
                    </span>
                  </td>
                  <td><span className="badge badge-xs badge-outline">{exp.exposure_type}</span></td>
                  <td className="font-mono text-base-content/70">{exp.asset_id}</td>
                  <td className="max-w-xs truncate" title={exp.description}>{exp.description}</td>
                  <td><span className="badge badge-xs badge-outline">{exp.status}</span></td>
                  <td>
                    {exp.status === 'OPEN' ? (
                      <button
                        onClick={() => setSelectedExp(exp)}
                        className="btn btn-xs btn-outline btn-success"
                      >
                        Resolve
                      </button>
                    ) : (
                      <span className="text-success font-semibold">Mitigated</span>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Resolve Exposure Modal */}
      {selectedExp && (
        <div className="modal modal-open">
          <div className="modal-box max-w-md">
            <h3 className="font-bold text-lg mb-2">
              ✅ Resolve Security Exposure
            </h3>
            <p className="text-xs text-base-content/70 mb-3">
              Mark exposure <span className="font-mono font-bold text-primary">{selectedExp.exposure_id}</span> ({selectedExp.category}) as mitigated.
            </p>
            <div className="form-control mb-4">
              <label className="label text-xs font-semibold">Resolution Notes / Reason:</label>
              <textarea
                className="textarea textarea-bordered text-xs h-20"
                placeholder="Describe mitigation steps taken (e.g. policy threshold adjusted, control verified)..."
                value={resolveReason}
                onChange={(e) => setResolveReason(e.target.value)}
              />
            </div>
            <div className="modal-action">
              <button
                onClick={() => setSelectedExp(null)}
                className="btn btn-sm btn-ghost"
                disabled={resolving}
              >
                Cancel
              </button>
              <button
                onClick={handleResolve}
                className="btn btn-sm btn-success"
                disabled={resolving}
              >
                {resolving ? 'Resolving...' : 'Confirm Resolution'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
