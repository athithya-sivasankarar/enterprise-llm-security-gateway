import React, { useState, useEffect } from 'react';
import { CheckCircle2, AlertTriangle, XCircle, Play, Shield, RefreshCw, Layers } from 'lucide-react';
import { DashboardService } from '../services/dashboardApi';

export default function ControlAssuranceCard({ apiKey }) {
  const [assurances, setAssurances] = useState([]);
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  const loadAssurances = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await DashboardService.getControlAssurance(apiKey);
      setAssurances(res || []);
    } catch (err) {
      setError(err.message || 'Failed to load control assurance matrix');
    } finally {
      setLoading(false);
    }
  };

  const handleRunAssurance = async () => {
    setRunning(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await DashboardService.runControlAssurance(null, apiKey);
      setAssurances(res || []);
      setSuccessMsg('Continuous control assurance evaluation completed successfully.');
    } catch (err) {
      setError(err.message || 'Failed to run control assurance');
    } finally {
      setRunning(false);
    }
  };

  useEffect(() => {
    loadAssurances();
  }, [apiKey]);

  const getStatusBadge = (status) => {
    switch (status) {
      case 'PASS':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-950/60 text-emerald-400 border border-emerald-800">
            <CheckCircle2 className="w-3 h-3" /> PASS
          </span>
        );
      case 'DEGRADED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-950/60 text-amber-400 border border-amber-800">
            <AlertTriangle className="w-3 h-3" /> DEGRADED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-950/60 text-rose-400 border border-rose-800">
            <XCircle className="w-3 h-3" /> GAP
          </span>
        );
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-cyan-950/60 border border-cyan-700/50 rounded-lg text-cyan-400">
            <Layers className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              Continuous Control Assurance Matrix
            </h2>
            <p className="text-xs text-slate-400">
              Evaluates actual test outcomes, regressions, incidents, and exposures against 14 security controls
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleRunAssurance}
            disabled={running}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded-lg transition disabled:opacity-50"
          >
            <Play className="w-3.5 h-3.5" />
            {running ? 'Evaluating...' : 'Run Assurance'}
          </button>
          <button
            onClick={loadAssurances}
            disabled={loading}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded-lg transition border border-slate-700"
          >
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>

      {successMsg && (
        <div className="p-3 bg-emerald-950/50 border border-emerald-800 rounded-lg text-emerald-300 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {error && (
        <div className="p-3 bg-rose-950/50 border border-rose-800 rounded-lg text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Assurance Table */}
      <div className="overflow-x-auto border border-slate-800 rounded-lg">
        <table className="w-full text-left text-xs text-slate-300">
          <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 uppercase tracking-wider font-semibold">
            <tr>
              <th className="px-4 py-3">Control / Domain</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Coverage %</th>
              <th className="px-4 py-3">Effectiveness Score</th>
              <th className="px-4 py-3">Test Stats</th>
              <th className="px-4 py-3">Gaps & Regs</th>
              <th className="px-4 py-3 text-right">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 bg-slate-900/40">
            {assurances.length === 0 ? (
              <tr>
                <td colSpan="7" className="px-4 py-8 text-center text-slate-500">
                  No control assurance data available. Click "Run Assurance" to execute assessment.
                </td>
              </tr>
            ) : (
              assurances.map((item) => (
                <tr key={item.control_id} className="hover:bg-slate-800/40 transition">
                  <td className="px-4 py-3">
                    <div className="font-semibold text-slate-200">{item.name || item.control_id}</div>
                    <div className="text-[11px] text-slate-400 font-mono">{item.control_id}</div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                      {item.control_type || 'PREVENTIVE'}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono font-bold text-slate-200">
                    {item.coverage_percentage?.toFixed(1)}%
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center space-x-2">
                      <span className="font-mono font-bold text-slate-100">
                        {item.effectiveness_score?.toFixed(1)}%
                      </span>
                      <div className="w-16 bg-slate-800 h-1.5 rounded-full overflow-hidden">
                        <div
                          className={`h-full ${
                            item.effectiveness_score >= 90
                              ? 'bg-emerald-500'
                              : item.effectiveness_score >= 70
                              ? 'bg-amber-500'
                              : 'bg-rose-500'
                          }`}
                          style={{ width: `${Math.min(100, Math.max(5, item.effectiveness_score || 0))}%` }}
                        />
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-slate-400 font-mono">
                    <span className="text-emerald-400">{item.passed_tests} pass</span> /{' '}
                    <span className={item.failed_tests > 0 ? 'text-rose-400 font-bold' : 'text-slate-400'}>
                      {item.failed_tests} fail
                    </span>{' '}
                    ({item.test_count} total)
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2 text-[11px] font-mono">
                      <span className={item.gap_count > 0 ? 'text-rose-400 font-bold' : 'text-slate-400'}>
                        {item.gap_count} gaps
                      </span>
                      <span className="text-slate-600">|</span>
                      <span className={item.regression_count > 0 ? 'text-amber-400 font-bold' : 'text-slate-400'}>
                        {item.regression_count} regs
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-right">
                    {getStatusBadge(item.last_status)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
