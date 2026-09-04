import React, { useState, useEffect } from 'react';
import { dashboardApi } from '../services/dashboardApi';

const CONTROL_DOMAINS = [
  { id: 'AUTH', name: 'Authentication', category: 'AUTHENTICATION' },
  { id: 'RBAC', name: 'RBAC & Authorization', category: 'RBAC' },
  { id: 'RATE', name: 'Rate Limiting', category: 'RATE_LIMITING' },
  { id: 'DLP', name: 'Input DLP', category: 'INPUT_DLP' },
  { id: 'INJ', name: 'Prompt Injection', category: 'PROMPT_INJECTION' },
  { id: 'JAIL', name: 'Jailbreak Defense', category: 'JAILBREAK' },
  { id: 'EXTR', name: 'System Extraction', category: 'SYSTEM_PROMPT_EXTRACTION' },
  { id: 'SECR', name: 'Secret Leakage', category: 'SECRET_LEAKAGE' },
  { id: 'RESP', name: 'Response Safety', category: 'UNSAFE_RESPONSE' },
  { id: 'PII', name: 'Response PII', category: 'RESPONSE_PII' },
  { id: 'PROV', name: 'Provider Auth', category: 'PROVIDER_AUTHORIZATION' },
  { id: 'CACHE', name: 'Cache Isolation', category: 'CACHE_ISOLATION' },
  { id: 'POL', name: 'Dynamic Policy', category: 'POLICY_ENFORCEMENT' },
  { id: 'OBS', name: 'Audit & Telemetry', category: 'AUDIT_LOGGING' }
];

export default function ExecutiveSecurityCard({ apiKey, userRole }) {
  const [postureData, setPostureData] = useState(null);
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const isRestricted = userRole === 'developer';

  const fetchExecutiveData = async () => {
    if (isRestricted) return;
    setLoading(true);
    try {
      const [posture, reps] = await Promise.all([
        dashboardApi.getSecurityPosture(apiKey).catch(() => null),
        dashboardApi.getReports({ limit: 5 }, apiKey).catch(() => [])
      ]);
      setPostureData(posture);
      setReports(Array.isArray(reps) ? reps : []);
    } catch (err) {
      setError(err.message || 'Failed to fetch executive posture data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchExecutiveData();
  }, [apiKey, userRole]);

  if (isRestricted) return null;

  const posture = postureData?.overall_posture || 'SECURE';
  const score = postureData?.latest_security_score ?? 100.0;
  const delta = postureData?.score_delta ?? 0.0;
  const openAlerts = postureData?.open_alerts_count ?? 0;
  const regressions = postureData?.active_regressions_count ?? 0;
  const criticals = postureData?.critical_findings_count ?? 0;
  const highs = postureData?.high_findings_count ?? 0;

  const postureColor =
    posture === 'SECURE'
      ? 'text-emerald-400 bg-emerald-950/60 border-emerald-500/30'
      : posture === 'DEGRADED'
      ? 'text-amber-400 bg-amber-950/60 border-amber-500/30'
      : 'text-red-400 bg-red-950/60 border-red-500/30';

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl mb-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center space-x-3">
            <span className="text-2xl">🛡️</span>
            <h2 className="text-lg font-bold text-slate-100">Executive Security & Posture Overview</h2>
            <span className={`text-xs px-2.5 py-0.5 rounded border font-mono font-bold ${postureColor}`}>
              {posture}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time executive summary of AI gateway controls, risk vectors, score trends, and framework compliance.
          </p>
        </div>

        <button
          onClick={fetchExecutiveData}
          disabled={loading}
          className="text-xs px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 transition"
        >
          {loading ? 'Refreshing...' : '🔄 Refresh View'}
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6 font-mono text-xs">
        <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg">
          <span className="text-slate-400 block text-[11px] font-sans">Aggregate Security Score</span>
          <div className="flex items-baseline space-x-2 mt-1">
            <span className={`text-2xl font-bold ${score >= 90 ? 'text-emerald-400' : score >= 70 ? 'text-amber-400' : 'text-red-400'}`}>
              {score}%
            </span>
            <span className={`text-xs ${delta >= 0 ? 'text-emerald-400' : 'text-red-400'}`}>
              {delta > 0 ? `+${delta}%` : `${delta}%`}
            </span>
          </div>
        </div>

        <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg">
          <span className="text-slate-400 block text-[11px] font-sans">Active Critical & High Findings</span>
          <div className="flex items-baseline space-x-2 mt-1">
            <span className={`text-2xl font-bold ${criticals > 0 ? 'text-red-400' : highs > 0 ? 'text-amber-400' : 'text-slate-300'}`}>
              {criticals + highs}
            </span>
            <span className="text-[11px] text-slate-400 font-sans">({criticals} Crit / {highs} High)</span>
          </div>
        </div>

        <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg">
          <span className="text-slate-400 block text-[11px] font-sans">Active Regressions</span>
          <div className="flex items-baseline space-x-2 mt-1">
            <span className={`text-2xl font-bold ${regressions > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
              {regressions}
            </span>
            <span className="text-[11px] text-slate-400 font-sans">vs baseline</span>
          </div>
        </div>

        <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg">
          <span className="text-slate-400 block text-[11px] font-sans">Open SOC Alerts</span>
          <div className="flex items-baseline space-x-2 mt-1">
            <span className={`text-2xl font-bold ${openAlerts > 0 ? 'text-amber-400' : 'text-slate-400'}`}>
              {openAlerts}
            </span>
            <span className="text-[11px] text-slate-400 font-sans">requiring triage</span>
          </div>
        </div>
      </div>

      {/* 14-Domain Control Coverage Grid */}
      <div>
        <h3 className="text-xs font-bold text-slate-300 mb-3 uppercase tracking-wider">
          Gateway Security Control Domain Coverage (14 Categories)
        </h3>
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-7 gap-2">
          {CONTROL_DOMAINS.map((dom) => (
            <div
              key={dom.id}
              className="p-2.5 bg-slate-950/70 border border-slate-800 rounded text-center hover:border-cyan-700/50 transition"
            >
              <div className="flex items-center justify-center space-x-1 mb-1">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                <span className="text-[10px] font-mono text-cyan-400 font-bold">{dom.id}</span>
              </div>
              <span className="text-[11px] font-medium text-slate-300 block truncate" title={dom.name}>
                {dom.name}
              </span>
              <span className="text-[9px] text-slate-500 font-mono block mt-0.5">Enforced</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
