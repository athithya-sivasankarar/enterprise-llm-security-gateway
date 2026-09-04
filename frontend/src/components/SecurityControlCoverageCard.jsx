import React, { useState, useEffect } from 'react';
import { dashboardApi } from '../services/dashboardApi';

export default function SecurityControlCoverageCard({ apiKey }) {
  const [coverageData, setCoverageData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('matrix'); // 'matrix' or 'gaps'

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await dashboardApi.getControlCoverage(null, apiKey);
      setCoverageData(data);
    } catch (err) {
      setError(err.message || 'Failed to calculate security control coverage');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [apiKey]);

  const getStatusBadge = (status) => {
    const s = (status || '').toUpperCase();
    if (s === 'PASS') return 'badge badge-success badge-sm';
    if (s === 'FAIL') return 'badge badge-error badge-sm';
    if (s === 'REGRESSION') return 'badge badge-warning badge-sm animate-pulse';
    if (s === 'DISABLED') return 'badge badge-ghost badge-sm';
    return 'badge badge-neutral badge-sm';
  };

  return (
    <div className="card shadow-lg bg-base-100 border border-base-200 p-5 rounded-2xl mb-6">
      <div className="flex flex-wrap justify-between items-center mb-4 gap-2">
        <div>
          <h2 className="text-xl font-bold flex items-center gap-2">
            <span>🛡️</span> Security Control Coverage & Gap Matrix
          </h2>
          <p className="text-xs text-base-content/70">
            Real-time mapping of Step 15 test categories and automated red-team validation to enterprise security controls.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="btn-group">
            <button
              className={`btn btn-xs ${activeTab === 'matrix' ? 'btn-primary' : 'btn-ghost'}`}
              onClick={() => setActiveTab('matrix')}
            >
              Control Matrix
            </button>
            <button
              className={`btn btn-xs ${activeTab === 'gaps' ? 'btn-primary' : 'btn-ghost'}`}
              onClick={() => setActiveTab('gaps')}
            >
              Gaps ({coverageData?.control_gaps_count || 0})
            </button>
          </div>
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

      {/* KPI Breakdown */}
      {coverageData && (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-5">
          <div className="bg-base-200/50 p-3 rounded-xl border border-base-300">
            <div className="text-xs text-base-content/70">Overall Coverage</div>
            <div className="text-2xl font-black text-primary">{coverageData.overall_coverage_pct}%</div>
          </div>
          <div className="bg-base-200/50 p-3 rounded-xl border border-base-300">
            <div className="text-xs text-base-content/70">Pass Rate</div>
            <div className="text-2xl font-black text-success">{coverageData.overall_pass_pct}%</div>
          </div>
          <div className="bg-base-200/50 p-3 rounded-xl border border-base-300">
            <div className="text-xs text-base-content/70">Controls Verified</div>
            <div className="text-2xl font-black text-base-content">{coverageData.passing_controls} / {coverageData.total_controls}</div>
          </div>
          <div className="bg-base-200/50 p-3 rounded-xl border border-base-300">
            <div className="text-xs text-base-content/70">Regressions</div>
            <div className={`text-2xl font-black ${coverageData.regression_controls > 0 ? 'text-warning' : 'text-base-content/60'}`}>
              {coverageData.regression_controls}
            </div>
          </div>
          <div className="bg-base-200/50 p-3 rounded-xl border border-base-300">
            <div className="text-xs text-base-content/70">Control Gaps</div>
            <div className={`text-2xl font-black ${coverageData.control_gaps_count > 0 ? 'text-error' : 'text-success'}`}>
              {coverageData.control_gaps_count}
            </div>
          </div>
        </div>
      )}

      {/* Matrix Tab */}
      {activeTab === 'matrix' && (
        <div className="overflow-x-auto">
          <table className="table table-zebra table-compact w-full text-xs">
            <thead>
              <tr>
                <th>Domain</th>
                <th>Control ID</th>
                <th>Control Name</th>
                <th>Type</th>
                <th>Tests Mapped</th>
                <th>Coverage</th>
                <th>Pass Rate</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="8" className="text-center py-4">Evaluating security controls...</td>
                </tr>
              ) : coverageData?.matrix?.map((item) => (
                <tr key={item.control_id} className="hover">
                  <td className="font-semibold">{item.domain}</td>
                  <td className="font-mono text-base-content/70">{item.control_id}</td>
                  <td className="font-bold">{item.name}</td>
                  <td><span className="badge badge-xs badge-ghost">{item.control_type}</span></td>
                  <td>{item.tests_executed} / {item.tests_mapped.length}</td>
                  <td>
                    <div className="flex items-center gap-2">
                      <progress
                        className="progress progress-primary w-16"
                        value={item.coverage_pct}
                        max="100"
                      />
                      <span>{item.coverage_pct.toFixed(0)}%</span>
                    </div>
                  </td>
                  <td>
                    <span className={item.pass_rate_pct >= 90 ? 'text-success font-bold' : item.pass_rate_pct > 0 ? 'text-warning font-bold' : 'text-base-content/40'}>
                      {item.pass_rate_pct.toFixed(0)}%
                    </span>
                  </td>
                  <td><span className={getStatusBadge(item.status)}>{item.status}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Gaps Tab */}
      {activeTab === 'gaps' && (
        <div className="space-y-3">
          {coverageData?.gaps?.length === 0 ? (
            <div className="text-center py-6 text-xs text-success font-semibold bg-success/10 rounded-xl border border-success/20">
              ✅ Zero security control gaps detected. All controls are tested, passing, and aligned with baseline policies.
            </div>
          ) : (
            coverageData?.gaps?.map((gap, idx) => (
              <div key={idx} className="p-3 bg-base-200/50 rounded-xl border border-base-300 text-xs">
                <div className="flex justify-between items-center mb-1">
                  <div className="font-bold flex items-center gap-2">
                    <span className={`badge badge-sm ${gap.severity === 'CRITICAL' ? 'badge-error' : 'badge-warning'}`}>
                      {gap.severity}
                    </span>
                    <span>{gap.domain} ({gap.control_id})</span>
                  </div>
                  <span className="badge badge-sm badge-outline">{gap.gap_type}</span>
                </div>
                <div className="text-base-content/80 mb-2">{gap.description}</div>
                <div className="bg-base-100 p-2 rounded-lg text-primary font-medium">
                  💡 Recommendation: {gap.recommendation}
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}
