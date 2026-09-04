import React, { useState, useEffect } from 'react';
import { dashboardApi } from '../services/dashboardApi';

export default function ThreatIntelligenceCard({ apiKey }) {
  const [summary, setSummary] = useState(null);
  const [indicators, setIndicators] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [catFilter, setCatFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [matchTargetCat, setMatchTargetCat] = useState('PROMPT_INJECTION');
  const [matches, setMatches] = useState(null);
  const [matching, setMatching] = useState(false);
  const [showMatchModal, setShowMatchModal] = useState(false);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [sumData, intelList] = await Promise.all([
        dashboardApi.getThreatIntelSummary(apiKey),
        dashboardApi.getThreatIntelligence({
          category: catFilter || undefined,
          indicator_type: typeFilter || undefined,
          limit: 50
        }, apiKey)
      ]);
      setSummary(sumData);
      setIndicators(intelList);
    } catch (err) {
      setError(err.message || 'Failed to load threat intelligence');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [apiKey, catFilter, typeFilter]);

  const handleMatchThreatIntel = async () => {
    try {
      setMatching(true);
      const res = await dashboardApi.matchThreatIntelligence({
        category: matchTargetCat
      }, apiKey);
      setMatches(res);
    } catch (e) {
      console.error('Matching failed:', e);
    } finally {
      setMatching(false);
    }
  };

  const getSevBadge = (sev) => {
    const s = (sev || '').toUpperCase();
    if (s === 'CRITICAL') return 'badge badge-error badge-sm';
    if (s === 'HIGH') return 'badge badge-warning badge-sm';
    if (s === 'MEDIUM') return 'badge badge-info badge-sm';
    return 'badge badge-ghost badge-sm';
  };

  return (
    <div className="card shadow-lg bg-base-100 border border-base-200 p-5 rounded-2xl mb-6">
      <div className="flex flex-wrap justify-between items-center mb-4 gap-2">
        <div>
          <h2 className="text-xl font-bold flex items-center gap-2">
            <span>🎯</span> Threat Intelligence & Indicator Mapping
          </h2>
          <p className="text-xs text-base-content/70">
            Deterministic mapping of MITRE ATLAS, MITRE ATT&CK, OWASP Top 10 for LLM, and CVE/CWE indicators (Metadata only).
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              setShowMatchModal(true);
              handleMatchThreatIntel();
            }}
            className="btn btn-sm btn-outline btn-primary"
          >
            🔍 Match Threat Intel
          </button>
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
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
          <div className="bg-base-200/50 p-3 rounded-xl border border-base-300">
            <div className="text-xs text-base-content/70">Total Indicators</div>
            <div className="text-2xl font-black text-primary">{summary.total_indicators}</div>
          </div>
          <div className="bg-base-200/50 p-3 rounded-xl border border-base-300">
            <div className="text-xs text-base-content/70">Critical Indicators</div>
            <div className="text-2xl font-black text-error">{summary.critical_indicators}</div>
          </div>
          <div className="bg-base-200/50 p-3 rounded-xl border border-base-300">
            <div className="text-xs text-base-content/70">High Indicators</div>
            <div className="text-2xl font-black text-warning">{summary.high_indicators}</div>
          </div>
          <div className="bg-base-200/50 p-3 rounded-xl border border-base-300">
            <div className="text-xs text-base-content/70">Categories Covered</div>
            <div className="text-2xl font-black text-success">{summary.categories_covered}</div>
          </div>
        </div>
      )}

      {/* Filter Controls */}
      <div className="flex flex-wrap gap-2 mb-3">
        <select
          className="select select-sm select-bordered text-xs"
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
        >
          <option value="">All Indicator Types</option>
          <option value="ATLAS_TECHNIQUE">MITRE ATLAS</option>
          <option value="OWASP_CATEGORY">OWASP Top 10 LLM</option>
          <option value="CWE">CWE Weakness</option>
          <option value="CVE">CVE Identifier</option>
        </select>
        <select
          className="select select-sm select-bordered text-xs"
          value={catFilter}
          onChange={(e) => setCatFilter(e.target.value)}
        >
          <option value="">All Categories</option>
          <option value="PROMPT_INJECTION">Prompt Injection</option>
          <option value="JAILBREAK">Jailbreak</option>
          <option value="SYSTEM_PROMPT_EXTRACTION">System Prompt</option>
          <option value="SECRET_LEAKAGE">Secret Leakage</option>
          <option value="INPUT_DLP">Input DLP</option>
          <option value="RBAC">RBAC</option>
          <option value="AUTHENTICATION">Authentication</option>
          <option value="RATE_LIMITING">Rate Limiting</option>
        </select>
      </div>

      {/* Indicators List Table */}
      <div className="overflow-x-auto">
        <table className="table table-zebra table-compact w-full text-xs">
          <thead>
            <tr>
              <th>Indicator ID</th>
              <th>Type</th>
              <th>Source</th>
              <th>Category</th>
              <th>Severity</th>
              <th>Confidence</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="7" className="text-center py-4">Loading threat intelligence catalog...</td>
              </tr>
            ) : indicators.length === 0 ? (
              <tr>
                <td colSpan="7" className="text-center py-4 text-base-content/50">No indicators matching selected filters.</td>
              </tr>
            ) : (
              indicators.map((ind) => (
                <tr key={ind.intel_id} className="hover">
                  <td className="font-mono font-bold text-primary">{ind.indicator}</td>
                  <td><span className="badge badge-xs badge-outline">{ind.indicator_type}</span></td>
                  <td>{ind.source}</td>
                  <td><span className="badge badge-xs badge-ghost">{ind.category}</span></td>
                  <td><span className={getSevBadge(ind.severity)}>{ind.severity}</span></td>
                  <td>{(ind.confidence * 100).toFixed(0)}%</td>
                  <td className="max-w-md truncate" title={ind.description}>{ind.description}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Interactive Threat Matcher Modal */}
      {showMatchModal && (
        <div className="modal modal-open">
          <div className="modal-box max-w-2xl">
            <h3 className="font-bold text-lg mb-2">
              🔍 Deterministic Threat Intelligence Matcher
            </h3>
            <p className="text-xs text-base-content/70 mb-4">
              Select a security domain to correlate against active CVE, ATLAS, OWASP, and CWE threat indicators.
            </p>

            <div className="flex gap-2 mb-4">
              <select
                className="select select-sm select-bordered flex-1 text-xs"
                value={matchTargetCat}
                onChange={(e) => setMatchTargetCat(e.target.value)}
              >
                <option value="PROMPT_INJECTION">PROMPT_INJECTION</option>
                <option value="JAILBREAK">JAILBREAK</option>
                <option value="SYSTEM_PROMPT_EXTRACTION">SYSTEM_PROMPT_EXTRACTION</option>
                <option value="SECRET_LEAKAGE">SECRET_LEAKAGE</option>
                <option value="INPUT_DLP">INPUT_DLP</option>
                <option value="RESPONSE_PII">RESPONSE_PII</option>
                <option value="RBAC">RBAC</option>
                <option value="AUTHENTICATION">AUTHENTICATION</option>
                <option value="RATE_LIMITING">RATE_LIMITING</option>
                <option value="CACHE_ISOLATION">CACHE_ISOLATION</option>
              </select>
              <button
                onClick={handleMatchThreatIntel}
                disabled={matching}
                className="btn btn-sm btn-primary"
              >
                {matching ? 'Matching...' : 'Evaluate Matches'}
              </button>
            </div>

            <div className="max-h-72 overflow-y-auto space-y-2">
              {matches?.length === 0 ? (
                <div className="text-center py-4 text-xs text-base-content/50">No matches found for category.</div>
              ) : (
                matches?.map((m, idx) => (
                  <div key={idx} className="p-3 bg-base-200/60 rounded-xl border border-base-300 text-xs">
                    <div className="flex justify-between items-center mb-1">
                      <span className="font-mono font-bold text-primary">{m.indicator} ({m.indicator_type})</span>
                      <span className="badge badge-sm badge-secondary">Relevance: {m.relevance_score}/100</span>
                    </div>
                    <div className="text-base-content/80 mb-1">{m.description}</div>
                    <div className="text-xs text-base-content/60 italic">{m.match_reason}</div>
                  </div>
                ))
              )}
            </div>

            <div className="modal-action">
              <button onClick={() => setShowMatchModal(false)} className="btn btn-sm">Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
