import React, { useState, useEffect } from 'react';
import { dashboardApi } from '../services/dashboardApi';

export default function SecurityAttackSurfaceCard({ apiKey }) {
  const [summary, setSummary] = useState(null);
  const [assets, setAssets] = useState([]);
  const [graph, setGraph] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [typeFilter, setTypeFilter] = useState('');
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [assetCoverage, setAssetCoverage] = useState(null);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [sumData, assetsData, graphData] = await Promise.all([
        dashboardApi.getAssetSummary(apiKey),
        dashboardApi.getAssets(typeFilter ? { asset_type: typeFilter } : {}, apiKey),
        dashboardApi.getAttackSurface(apiKey)
      ]);
      setSummary(sumData);
      setAssets(assetsData);
      setGraph(graphData);
    } catch (err) {
      setError(err.message || 'Failed to load attack surface inventory');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [apiKey, typeFilter]);

  const handleSelectAsset = async (asset) => {
    setSelectedAsset(asset);
    try {
      const cov = await dashboardApi.getAssetCoverage(asset.asset_id, apiKey);
      setAssetCoverage(cov);
    } catch (e) {
      console.error('Failed to load asset coverage:', e);
    }
  };

  const getCritBadge = (crit) => {
    const c = (crit || '').toUpperCase();
    if (c === 'CRITICAL') return 'badge badge-error';
    if (c === 'HIGH') return 'badge badge-warning';
    if (c === 'MEDIUM') return 'badge badge-info';
    return 'badge badge-success';
  };

  return (
    <div className="card shadow-lg bg-base-100 border border-base-200 p-5 rounded-2xl mb-6">
      <div className="flex flex-wrap justify-between items-center mb-4 gap-2">
        <div>
          <h2 className="text-xl font-bold flex items-center gap-2">
            <span>🌐</span> Attack Surface Mapping & Asset Inventory
          </h2>
          <p className="text-xs text-base-content/70">
            Logical gateway component hierarchy, AI asset inventory, and multidimensional test coverage.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select
            className="select select-sm select-bordered"
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
          >
            <option value="">All Asset Types</option>
            <option value="LLM_MODEL">LLM Model</option>
            <option value="API">API Endpoint</option>
            <option value="DATABASE">Database</option>
            <option value="CACHE">Cache</option>
            <option value="APPLICATION">Application</option>
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
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
          <div className="bg-base-200/50 p-3 rounded-xl border border-base-300">
            <div className="text-xs text-base-content/70">Total Assets</div>
            <div className="text-2xl font-black text-primary">{summary.total_assets}</div>
          </div>
          <div className="bg-base-200/50 p-3 rounded-xl border border-base-300">
            <div className="text-xs text-base-content/70">Critical Assets</div>
            <div className="text-2xl font-black text-error">{summary.critical_assets}</div>
          </div>
          <div className="bg-base-200/50 p-3 rounded-xl border border-base-300">
            <div className="text-xs text-base-content/70">Test Coverage</div>
            <div className="text-2xl font-black text-success">{summary.overall_coverage_pct}%</div>
          </div>
          <div className="bg-base-200/50 p-3 rounded-xl border border-base-300">
            <div className="text-xs text-base-content/70">Avg Risk Score</div>
            <div className="text-2xl font-black text-warning">{summary.avg_asset_risk_score} / 100</div>
          </div>
        </div>
      )}

      {/* Logical Gateway Dataflow Architecture Banner */}
      <div className="bg-base-200/40 p-3 rounded-xl border border-base-300 mb-5 text-xs">
        <div className="font-semibold text-base-content/80 mb-1">🏛️ Gateway Architecture Dataflow (Zero Probing / Logical Mapping):</div>
        <div className="flex flex-wrap items-center gap-2 text-base-content/70">
          <span className="badge badge-outline">Client / UI</span> ➔
          <span className="badge badge-outline">API Gateway</span> ➔
          <span className="badge badge-outline badge-primary">Security Controls (DLP/RBAC/PI)</span> ➔
          <span className="badge badge-outline badge-secondary">Multi-Provider LLMs</span> ➔
          <span className="badge badge-outline">Output Filter</span> ➔
          <span className="badge badge-outline">PostgreSQL & Redis Cache</span>
        </div>
      </div>

      {/* Asset Inventory Table */}
      <div className="overflow-x-auto">
        <table className="table table-zebra table-compact w-full text-xs">
          <thead>
            <tr>
              <th>Asset Name</th>
              <th>Type</th>
              <th>Criticality</th>
              <th>Provider / Model</th>
              <th>Risk Score</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="7" className="text-center py-4">Loading attack surface assets...</td>
              </tr>
            ) : assets.length === 0 ? (
              <tr>
                <td colSpan="7" className="text-center py-4 text-base-content/50">No assets discovered matching filter.</td>
              </tr>
            ) : (
              assets.map((a) => (
                <tr key={a.asset_id} className="hover">
                  <td className="font-bold">{a.name}</td>
                  <td><span className="badge badge-sm badge-ghost">{a.asset_type}</span></td>
                  <td><span className={getCritBadge(a.criticality)}>{a.criticality}</span></td>
                  <td>{a.provider ? `${a.provider} ${a.model ? `(${a.model})` : ''}` : '-'}</td>
                  <td>
                    <span className={`font-mono font-bold ${a.risk_score >= 60 ? 'text-error' : a.risk_score >= 30 ? 'text-warning' : 'text-success'}`}>
                      {a.risk_score}
                    </span>
                  </td>
                  <td><span className="badge badge-sm badge-outline">{a.status}</span></td>
                  <td>
                    <button
                      onClick={() => handleSelectAsset(a)}
                      className="btn btn-xs btn-outline btn-primary"
                    >
                      View Coverage
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Asset Coverage Modal / Drawer */}
      {selectedAsset && (
        <div className="modal modal-open">
          <div className="modal-box max-w-xl">
            <h3 className="font-bold text-lg mb-2">
              🛡️ Asset Security Coverage: {selectedAsset.name}
            </h3>
            <div className="text-xs space-y-2 mb-4">
              <div><strong>Asset ID:</strong> <span className="font-mono">{selectedAsset.asset_id}</span></div>
              <div><strong>Type:</strong> {selectedAsset.asset_type} | <strong>Criticality:</strong> {selectedAsset.criticality}</div>
              <div><strong>Environment:</strong> {selectedAsset.environment} | <strong>Endpoint:</strong> {selectedAsset.endpoint || '-'}</div>
            </div>

            {assetCoverage && (
              <div className="space-y-3 text-xs bg-base-200/50 p-3 rounded-xl border border-base-300">
                <div className="flex justify-between items-center">
                  <span>Coverage Percentage:</span>
                  <span className="font-bold text-success text-sm">{assetCoverage.coverage_pct}%</span>
                </div>
                <div>
                  <strong>Mapped Security Controls:</strong>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {assetCoverage.controls_mapped.map((c) => (
                      <span key={c} className="badge badge-sm badge-secondary">{c}</span>
                    ))}
                  </div>
                </div>
                <div>
                  <strong>Mapped Automated Tests:</strong>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {assetCoverage.tests_mapped.map((t) => (
                      <span key={t} className="badge badge-sm badge-outline">{t}</span>
                    ))}
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-2 pt-2 text-center">
                  <div className="bg-base-100 p-2 rounded">Findings: <strong>{assetCoverage.findings_count}</strong></div>
                  <div className="bg-base-100 p-2 rounded">Active Incidents: <strong>{assetCoverage.active_incidents_count}</strong></div>
                  <div className="bg-base-100 p-2 rounded">Exposures: <strong>{assetCoverage.exposures_count}</strong></div>
                </div>
              </div>
            )}

            <div className="modal-action">
              <button onClick={() => setSelectedAsset(null)} className="btn btn-sm">Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
