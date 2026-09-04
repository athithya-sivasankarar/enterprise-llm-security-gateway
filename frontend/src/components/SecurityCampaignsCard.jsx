import React, { useState, useEffect } from 'react';
import {
  GitCompare,
  TrendingDown,
  TrendingUp,
  AlertTriangle,
  Play,
  Plus,
  RefreshCw,
  Pause,
  Clock,
  Shield,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  ChevronDown,
  ChevronUp,
  Layers,
  History,
  Bookmark
} from 'lucide-react';
import { DashboardService } from '../services/dashboardApi';

const AVAILABLE_CATEGORIES = [
  'AUTHENTICATION',
  'RBAC',
  'RATE_LIMITING',
  'INPUT_DLP',
  'PROMPT_INJECTION',
  'JAILBREAK',
  'SYSTEM_PROMPT_EXTRACTION',
  'SECRET_LEAKAGE',
  'UNSAFE_CONTENT',
  'RESPONSE_PII',
  'CACHE_ISOLATION',
  'POLICY',
  'AUDIT',
  'OBSERVABILITY'
];

export default function SecurityCampaignsCard({ role, apiKey }) {
  const [campaigns, setCampaigns] = useState([]);
  const [selectedCampaign, setSelectedCampaign] = useState(null);
  const [campaignRuns, setCampaignRuns] = useState([]);
  const [regressions, setRegressions] = useState([]);
  const [latestComparison, setLatestComparison] = useState(null);
  const [isExecuting, setIsExecuting] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  // Create Campaign Modal State
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newCampName, setNewCampName] = useState('');
  const [newCampDesc, setNewCampDesc] = useState('');
  const [newCampCategories, setNewCampCategories] = useState([]);
  const [newCampSchedule, setNewCampSchedule] = useState('daily');
  const [newCampScheduleEnabled, setNewCampScheduleEnabled] = useState(false);

  const canManage = role && (role.toLowerCase() === 'admin' || role.toLowerCase() === 'analyst');

  const fetchCampaignsData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await DashboardService.getCampaigns(apiKey);
      setCampaigns(data || []);

      if (data && data.length > 0) {
        const activeCamp = selectedCampaign ? data.find(c => c.campaign_id === selectedCampaign.campaign_id) || data[0] : data[0];
        setSelectedCampaign(activeCamp);
        await loadCampaignDetails(activeCamp.campaign_id);
      }
    } catch (err) {
      console.error('Failed to load campaigns:', err);
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const loadCampaignDetails = async (campaignId) => {
    try {
      const [runsData, regsData] = await Promise.all([
        DashboardService.getCampaignRuns(campaignId, apiKey).catch(() => []),
        DashboardService.getCampaignRegressions(campaignId, apiKey).catch(() => [])
      ]);
      setCampaignRuns(runsData || []);
      setRegressions(regsData || []);
    } catch (err) {
      console.error('Failed to load campaign details:', err);
    }
  };

  useEffect(() => {
    fetchCampaignsData();
  }, [apiKey]);

  const handleSelectCampaign = async (camp) => {
    setSelectedCampaign(camp);
    setLatestComparison(null);
    await loadCampaignDetails(camp.campaign_id);
  };

  const handleCreateCampaign = async (e) => {
    e.preventDefault();
    if (!newCampName.trim()) return;

    try {
      await DashboardService.createCampaign({
        name: newCampName.trim(),
        description: newCampDesc.trim() || null,
        category_filter: newCampCategories,
        schedule_enabled: newCampScheduleEnabled,
        schedule_interval: newCampSchedule
      }, apiKey);

      setShowCreateModal(false);
      setNewCampName('');
      setNewCampDesc('');
      setNewCampCategories([]);
      await fetchCampaignsData();
    } catch (err) {
      alert(`Failed to create campaign: ${err.message}`);
    }
  };

  const handleExecuteCampaign = async (campaignId) => {
    if (!campaignId) return;
    setIsExecuting(true);
    setError(null);
    try {
      const res = await DashboardService.executeCampaign(campaignId, apiKey);
      if (res && res.comparison) {
        setLatestComparison(res.comparison);
      }
      await fetchCampaignsData();
      await loadCampaignDetails(campaignId);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsExecuting(false);
    }
  };

  const handlePauseResume = async (campaign) => {
    try {
      if (campaign.status === 'ACTIVE') {
        await DashboardService.pauseCampaign(campaign.campaign_id, apiKey);
      } else {
        await DashboardService.resumeCampaign(campaign.campaign_id, apiKey);
      }
      await fetchCampaignsData();
    } catch (err) {
      alert(`Action failed: ${err.message}`);
    }
  };

  const toggleCategory = (cat) => {
    if (newCampCategories.includes(cat)) {
      setNewCampCategories(newCampCategories.filter(c => c !== cat));
    } else {
      setNewCampCategories([...newCampCategories, cat]);
    }
  };

  // KPI Calculations
  const totalCampaigns = campaigns.length;
  const activeCampaigns = campaigns.filter(c => c.status === 'ACTIVE').length;
  const totalRegressions = regressions.length;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl mb-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-6 border-b border-slate-800 gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-indigo-500/10 border border-indigo-500/30 rounded-lg text-indigo-400">
              <GitCompare className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
                Security Assessment Campaigns & Regression Engine
                <span className="px-2 py-0.5 text-xs font-semibold bg-indigo-950 text-indigo-400 border border-indigo-800 rounded-full">
                  Continuous QA
                </span>
              </h2>
              <p className="text-sm text-slate-400">
                Baseline tracking, delta score comparisons, and individual test regression detection across security policies.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchCampaignsData}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>

          {canManage && (
            <button
              onClick={() => setShowCreateModal(true)}
              className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-white bg-indigo-600 hover:bg-indigo-500 rounded-lg shadow-sm transition"
            >
              <Plus className="w-4 h-4" />
              New Campaign
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="mt-4 p-3 bg-red-950/60 border border-red-800/80 rounded-lg text-xs text-red-200 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 my-6">
        <div className="bg-slate-950/60 border border-slate-800/80 p-4 rounded-lg">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Total Campaigns</span>
          <div className="text-2xl font-bold text-slate-100 mt-1">{totalCampaigns}</div>
        </div>
        <div className="bg-slate-950/60 border border-slate-800/80 p-4 rounded-lg">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Active Campaigns</span>
          <div className="text-2xl font-bold text-emerald-400 mt-1">{activeCampaigns}</div>
        </div>
        <div className="bg-slate-950/60 border border-slate-800/80 p-4 rounded-lg">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Latest Score</span>
          <div className="text-2xl font-bold text-indigo-400 mt-1">
            {selectedCampaign?.latest_score !== null && selectedCampaign?.latest_score !== undefined
              ? `${selectedCampaign.latest_score}%`
              : 'N/A'}
          </div>
        </div>
        <div className="bg-slate-950/60 border border-slate-800/80 p-4 rounded-lg">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Regressions</span>
          <div className={`text-2xl font-bold mt-1 ${totalRegressions > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
            {totalRegressions}
          </div>
        </div>
      </div>

      {/* Main Campaign Work Area */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Campaigns List */}
        <div className="lg:col-span-1 space-y-3">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Assessment Campaigns</h3>
          {campaigns.length === 0 ? (
            <div className="p-6 bg-slate-950/40 border border-slate-800 rounded-lg text-center text-xs text-slate-400">
              No campaigns created yet. Click "New Campaign" to set up continuous security validation.
            </div>
          ) : (
            <div className="space-y-2 max-h-[420px] overflow-y-auto pr-1">
              {campaigns.map((camp) => {
                const isSelected = selectedCampaign?.campaign_id === camp.campaign_id;
                const scoreDelta = camp.score_delta;
                return (
                  <div
                    key={camp.campaign_id}
                    onClick={() => handleSelectCampaign(camp)}
                    className={`p-3.5 rounded-lg border cursor-pointer transition ${
                      isSelected
                        ? 'bg-indigo-950/40 border-indigo-500/60 shadow-md'
                        : 'bg-slate-950/40 border-slate-800/80 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-semibold text-slate-100">{camp.name}</span>
                      <span
                        className={`px-2 py-0.5 text-[10px] font-bold rounded-full border ${
                          camp.status === 'ACTIVE'
                            ? 'bg-emerald-950/70 text-emerald-400 border-emerald-800'
                            : camp.status === 'PAUSED'
                            ? 'bg-yellow-950/70 text-yellow-400 border-yellow-800'
                            : 'bg-slate-900 text-slate-400 border-slate-700'
                        }`}
                      >
                        {camp.status}
                      </span>
                    </div>

                    {camp.description && (
                      <p className="text-xs text-slate-400 mt-1 line-clamp-1">{camp.description}</p>
                    )}

                    <div className="flex items-center justify-between mt-3 pt-2 border-t border-slate-800/60 text-xs">
                      <div className="flex items-center gap-1.5 text-slate-400">
                        <Clock className="w-3.5 h-3.5" />
                        <span>{camp.schedule_enabled ? camp.schedule_interval : 'Manual'}</span>
                      </div>

                      {scoreDelta !== null && scoreDelta !== undefined && (
                        <div
                          className={`flex items-center gap-1 font-semibold ${
                            scoreDelta < 0
                              ? 'text-red-400'
                              : scoreDelta > 0
                              ? 'text-emerald-400'
                              : 'text-slate-400'
                          }`}
                        >
                          {scoreDelta < 0 ? <TrendingDown className="w-3.5 h-3.5" /> : <TrendingUp className="w-3.5 h-3.5" />}
                          <span>{scoreDelta > 0 ? `+${scoreDelta}%` : `${scoreDelta}%`}</span>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Right Column: Selected Campaign Workspace */}
        <div className="lg:col-span-2 bg-slate-950/60 border border-slate-800 rounded-xl p-5">
          {selectedCampaign ? (
            <div>
              {/* Campaign Header & Controls */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
                <div>
                  <h3 className="text-lg font-bold text-slate-100">{selectedCampaign.name}</h3>
                  <div className="flex items-center gap-2 text-xs text-slate-400 mt-1">
                    <span>ID: <code className="text-slate-300">{selectedCampaign.campaign_id}</code></span>
                    <span>•</span>
                    <span>Policy: v{selectedCampaign.policy_version}</span>
                    <span>•</span>
                    <span>Baseline: {selectedCampaign.baseline_run_id || 'Initial'}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {canManage && (
                    <>
                      <button
                        onClick={() => handlePauseResume(selectedCampaign)}
                        className="px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition"
                      >
                        {selectedCampaign.status === 'ACTIVE' ? 'Pause' : 'Resume'}
                      </button>
                      <button
                        onClick={() => handleExecuteCampaign(selectedCampaign.campaign_id)}
                        disabled={isExecuting || selectedCampaign.status === 'ARCHIVED'}
                        className="flex items-center gap-1.5 px-4 py-1.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 rounded-lg shadow transition"
                      >
                        <Play className={`w-3.5 h-3.5 ${isExecuting ? 'animate-spin' : ''}`} />
                        {isExecuting ? 'Running Validation...' : 'Execute Campaign'}
                      </button>
                    </>
                  )}
                </div>
              </div>

              {/* Latest Comparison Alert / Summary */}
              {latestComparison && (
                <div
                  className={`mt-4 p-4 rounded-lg border text-xs ${
                    latestComparison.regression_detected
                      ? 'bg-red-950/40 border-red-800 text-red-200'
                      : 'bg-emerald-950/30 border-emerald-800/80 text-emerald-200'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 font-bold text-sm">
                      {latestComparison.regression_detected ? (
                        <>
                          <ShieldAlert className="w-4 h-4 text-red-400" />
                          <span>REGRESSION DETECTED IN CAMPAIGN RUN</span>
                        </>
                      ) : (
                        <>
                          <ShieldCheck className="w-4 h-4 text-emerald-400" />
                          <span>CAMPAIGN RUN PASSED — NO REGRESSIONS</span>
                        </>
                      )}
                    </div>
                    <span className="font-mono">
                      Delta: {latestComparison.score_delta > 0 ? `+${latestComparison.score_delta}%` : `${latestComparison.score_delta}%`}
                    </span>
                  </div>

                  {latestComparison.new_failures && latestComparison.new_failures.length > 0 && (
                    <div className="mt-2 text-red-300">
                      <strong>Newly Failing Tests:</strong> {latestComparison.new_failures.join(', ')}
                    </div>
                  )}

                  {latestComparison.resolved_failures && latestComparison.resolved_failures.length > 0 && (
                    <div className="mt-1 text-emerald-300">
                      <strong>Resolved Failures:</strong> {latestComparison.resolved_failures.join(', ')}
                    </div>
                  )}
                </div>
              )}

              {/* Active Regressions Table */}
              <div className="mt-5">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                    Recorded Test Regressions
                  </h4>
                  <span className="text-xs text-slate-500">{regressions.length} total</span>
                </div>

                {regressions.length === 0 ? (
                  <div className="p-4 bg-slate-900/40 border border-slate-800/60 rounded-lg text-center text-xs text-slate-400">
                    No active security regressions recorded for this campaign.
                  </div>
                ) : (
                  <div className="space-y-2 max-h-[160px] overflow-y-auto">
                    {regressions.map((reg) => (
                      <div
                        key={reg.regression_id}
                        className="p-2.5 bg-red-950/20 border border-red-900/40 rounded-lg flex items-center justify-between text-xs"
                      >
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-red-300">{reg.test_id}</span>
                            <span className="px-1.5 py-0.2 bg-red-950 text-red-400 border border-red-800 rounded text-[10px]">
                              {reg.category}
                            </span>
                            <span className="text-slate-400">
                              {reg.previous_status} → <strong className="text-red-400">{reg.current_status}</strong>
                            </span>
                          </div>
                          <p className="text-slate-400 text-[11px]">{reg.description}</p>
                        </div>
                        <span className="font-mono text-red-400 font-bold">{reg.score_delta}%</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Campaign Run History */}
              <div className="mt-6">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                    <History className="w-3.5 h-3.5 text-indigo-400" />
                    Execution History
                  </h4>
                </div>

                {campaignRuns.length === 0 ? (
                  <div className="p-4 bg-slate-900/40 border border-slate-800/60 rounded-lg text-center text-xs text-slate-400">
                    No runs recorded yet. Click "Execute Campaign" to initiate the first run.
                  </div>
                ) : (
                  <div className="border border-slate-800 rounded-lg overflow-hidden">
                    <table className="w-full text-xs text-left">
                      <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 font-medium">
                        <tr>
                          <th className="py-2 px-3">Run ID</th>
                          <th className="py-2 px-3">Status</th>
                          <th className="py-2 px-3">Score</th>
                          <th className="py-2 px-3">Delta</th>
                          <th className="py-2 px-3">Regression</th>
                          <th className="py-2 px-3">Started</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {campaignRuns.map((r) => (
                          <tr key={r.campaign_run_id} className="hover:bg-slate-900/40">
                            <td className="py-2 px-3 font-mono text-slate-300">{r.run_id}</td>
                            <td className="py-2 px-3">
                              <span
                                className={`px-2 py-0.5 text-[10px] font-bold rounded-full ${
                                  r.status === 'COMPLETED'
                                    ? 'bg-emerald-950 text-emerald-400'
                                    : 'bg-red-950 text-red-400'
                                }`}
                              >
                                {r.status}
                              </span>
                            </td>
                            <td className="py-2 px-3 font-bold text-slate-200">{r.security_score}%</td>
                            <td className="py-2 px-3 font-mono">
                              {r.score_delta !== null && r.score_delta !== undefined ? (
                                <span className={r.score_delta < 0 ? 'text-red-400' : 'text-emerald-400'}>
                                  {r.score_delta > 0 ? `+${r.score_delta}%` : `${r.score_delta}%`}
                                </span>
                              ) : (
                                <span className="text-slate-500">—</span>
                              )}
                            </td>
                            <td className="py-2 px-3">
                              {r.regression_detected ? (
                                <span className="text-red-400 font-semibold flex items-center gap-1">
                                  <AlertTriangle className="w-3 h-3" /> Yes
                                </span>
                              ) : (
                                <span className="text-emerald-400 font-semibold flex items-center gap-1">
                                  <CheckCircle2 className="w-3 h-3" /> No
                                </span>
                              )}
                            </td>
                            <td className="py-2 px-3 text-slate-400">
                              {new Date(r.started_at).toLocaleTimeString()}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="p-12 text-center text-xs text-slate-500">
              Select or create a campaign to view execution history and baseline tracking.
            </div>
          )}
        </div>
      </div>

      {/* Modal: Create Assessment Campaign */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <Plus className="w-5 h-5 text-indigo-400" />
                Create Security Assessment Campaign
              </h3>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-slate-200"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateCampaign} className="space-y-3.5 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Campaign Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Daily Zero-Trust & Injection Audit"
                  value={newCampName}
                  onChange={(e) => setNewCampName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Description (Optional)</label>
                <input
                  type="text"
                  placeholder="Continuous adversarial regression tracking"
                  value={newCampDesc}
                  onChange={(e) => setNewCampDesc(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Schedule Interval</label>
                <select
                  value={newCampSchedule}
                  onChange={(e) => setNewCampSchedule(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-indigo-500"
                >
                  <option value="hourly">Hourly</option>
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Category Filter (Leave empty to test all 14 categories)
                </label>
                <div className="grid grid-cols-2 gap-1.5 max-h-36 overflow-y-auto p-2 bg-slate-950 border border-slate-800 rounded-lg">
                  {AVAILABLE_CATEGORIES.map((cat) => (
                    <label key={cat} className="flex items-center gap-2 text-slate-300 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={newCampCategories.includes(cat)}
                        onChange={() => toggleCategory(cat)}
                        className="rounded bg-slate-900 border-slate-700 text-indigo-600 focus:ring-0"
                      />
                      <span className="text-[11px] truncate">{cat}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-medium rounded-lg shadow transition"
                >
                  Create Campaign
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
