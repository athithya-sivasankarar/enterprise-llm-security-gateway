import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle2, XCircle, Clock, FileText, Activity, Layers } from 'lucide-react';
import { DashboardService } from '../services/dashboardApi';

export default function SecurityGovernanceCard({ apiKey }) {
  const [summary, setSummary] = useState(null);
  const [risk, setRisk] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [sumRes, riskRes] = await Promise.all([
        DashboardService.getGovernanceSummary(apiKey),
        DashboardService.getGovernanceRisk(apiKey)
      ]);
      setSummary(sumRes);
      setRisk(riskRes);
    } catch (err) {
      setError(err.message || 'Failed to load governance posture');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [apiKey]);

  if (loading && !summary) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
        <div className="animate-pulse flex space-x-4">
          <div className="flex-1 space-y-4 py-1">
            <div className="h-4 bg-slate-700 rounded w-3/4"></div>
            <div className="h-24 bg-slate-800 rounded"></div>
          </div>
        </div>
      </div>
    );
  }

  const riskScore = summary?.governance_risk_score ?? 0;
  const riskLevel = summary?.governance_risk_level ?? 'LOW';
  const assuranceScore = summary?.control_assurance_score ?? 100.0;
  const coveragePct = summary?.control_coverage_percentage ?? 100.0;

  const getRiskColor = (level) => {
    switch (level) {
      case 'CRITICAL': return 'text-rose-400 bg-rose-950/40 border-rose-800';
      case 'HIGH': return 'text-orange-400 bg-orange-950/40 border-orange-800';
      case 'MEDIUM': return 'text-amber-400 bg-amber-950/40 border-amber-800';
      default: return 'text-emerald-400 bg-emerald-950/40 border-emerald-800';
    }
  };

  const getScoreBadgeColor = (score) => {
    if (score >= 90) return 'text-emerald-400';
    if (score >= 70) return 'text-amber-400';
    return 'text-rose-400';
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-6">
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-indigo-950/60 border border-indigo-700/50 rounded-lg text-indigo-400">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              Security Governance & Risk Acceptance
              <span className="text-xs px-2.5 py-0.5 rounded-full bg-indigo-950/80 text-indigo-300 border border-indigo-700/60 font-semibold">
                Step 21 Posture
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Continuous control assurance, bounded risk exceptions, and governed security decisions
            </p>
          </div>
        </div>
        <button
          onClick={loadData}
          disabled={loading}
          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded-lg transition border border-slate-700"
        >
          {loading ? 'Refreshing...' : 'Refresh Posture'}
        </button>
      </div>

      {error && (
        <div className="p-3 bg-rose-950/50 border border-rose-800 rounded-lg text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Main KPI Gauges */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Governance Risk Score */}
        <div className="p-4 bg-slate-950/60 border border-slate-800 rounded-lg space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-medium">Governance Risk</span>
            <span className={`text-xs px-2 py-0.5 rounded border font-semibold ${getRiskColor(riskLevel)}`}>
              {riskLevel}
            </span>
          </div>
          <div className="flex items-baseline space-x-2">
            <span className={`text-3xl font-extrabold ${getRiskColor(riskLevel).split(' ')[0]}`}>
              {riskScore}
            </span>
            <span className="text-xs text-slate-500 font-mono">/ 100</span>
          </div>
          <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
            <div
              className={`h-full transition-all duration-500 ${
                riskScore >= 80 ? 'bg-rose-500' : riskScore >= 60 ? 'bg-orange-500' : riskScore >= 30 ? 'bg-amber-500' : 'bg-emerald-500'
              }`}
              style={{ width: `${Math.min(100, Math.max(5, riskScore))}%` }}
            />
          </div>
        </div>

        {/* Control Assurance Effectiveness */}
        <div className="p-4 bg-slate-950/60 border border-slate-800 rounded-lg space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-medium">Control Assurance</span>
            <span className="text-xs text-slate-400 font-mono">{summary?.effective_controls || 14}/{summary?.total_controls || 14} PASS</span>
          </div>
          <div className="flex items-baseline space-x-2">
            <span className={`text-3xl font-extrabold ${getScoreBadgeColor(assuranceScore)}`}>
              {assuranceScore.toFixed(1)}%
            </span>
          </div>
          <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
            <div
              className={`h-full transition-all duration-500 ${
                assuranceScore >= 90 ? 'bg-emerald-500' : assuranceScore >= 70 ? 'bg-amber-500' : 'bg-rose-500'
              }`}
              style={{ width: `${Math.min(100, Math.max(5, assuranceScore))}%` }}
            />
          </div>
        </div>

        {/* Risk Exceptions */}
        <div className="p-4 bg-slate-950/60 border border-slate-800 rounded-lg space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-medium">Active Exceptions</span>
            {summary?.overdue_exceptions > 0 ? (
              <span className="text-xs px-2 py-0.5 rounded bg-rose-950/60 text-rose-400 border border-rose-800 font-semibold">
                {summary.overdue_exceptions} OVERDUE
              </span>
            ) : (
              <span className="text-xs px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800">
                IN COMPLIANCE
              </span>
            )}
          </div>
          <div className="flex items-baseline space-x-3">
            <span className="text-3xl font-extrabold text-slate-100">
              {summary?.open_exceptions ?? 0}
            </span>
            <span className="text-xs text-slate-400">
              ({summary?.pending_approval_exceptions ?? 0} pending, {summary?.expired_exceptions ?? 0} expired)
            </span>
          </div>
          <p className="text-[10px] text-slate-500">
            Mandatory expiration enforced
          </p>
        </div>

        {/* Unmitigated Exposures & Incidents */}
        <div className="p-4 bg-slate-950/60 border border-slate-800 rounded-lg space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-medium">Underlying Findings</span>
            <span className="text-xs text-slate-400 font-mono">Steps 19 & 20</span>
          </div>
          <div className="flex items-center gap-3">
            <div>
              <div className="text-lg font-bold text-rose-400">{summary?.critical_exposures ?? 0}</div>
              <div className="text-[10px] text-slate-400 uppercase font-semibold">Crit Exposures</div>
            </div>
            <div className="border-l border-slate-800 pl-3">
              <div className="text-lg font-bold text-amber-400">{summary?.open_incidents ?? 0}</div>
              <div className="text-[10px] text-slate-400 uppercase font-semibold">Incidents</div>
            </div>
            <div className="border-l border-slate-800 pl-3">
              <div className="text-lg font-bold text-indigo-400">{summary?.control_gaps ?? 0}</div>
              <div className="text-[10px] text-slate-400 uppercase font-semibold">Ctrl Gaps</div>
            </div>
          </div>
          <p className="text-[10px] text-slate-500">
            {summary?.active_regressions ?? 0} active test regression(s)
          </p>
        </div>
      </div>

      {/* Contributing Risk Factors Breakdown */}
      {risk?.factors && risk.factors.length > 0 && (
        <div className="space-y-3 pt-2">
          <h3 className="text-sm font-semibold text-slate-300 flex items-center gap-2">
            <Activity className="w-4 h-4 text-indigo-400" />
            Contributing Governance Risk Factors
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
            {risk.factors.map((f, idx) => (
              <div
                key={idx}
                className="p-3 bg-slate-950/40 border border-slate-800/80 rounded-lg flex items-start justify-between space-x-3"
              >
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-semibold text-slate-200">{f.factor.replace(/_/g, ' ')}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                      count: {f.count}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">{f.description}</p>
                </div>
                <div className="text-right flex-shrink-0">
                  <span className="text-xs font-bold text-rose-400 font-mono">+{f.contribution}</span>
                  <div className="text-[10px] text-slate-500">pts</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
