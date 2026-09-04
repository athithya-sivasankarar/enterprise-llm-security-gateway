import React, { useState, useEffect } from 'react';
import { ClipboardCheck, Plus, CheckCircle, FileText, User, Calendar, AlertCircle } from 'lucide-react';
import { DashboardService } from '../services/dashboardApi';

export default function GovernanceReviewCard({ apiKey }) {
  const [reviews, setReviews] = useState([]);
  const [loading, setLoading] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  const [formData, setFormData] = useState({
    review_type: 'CONTROL_EFFECTIVENESS',
    scope: 'enterprise',
    reviewer: 'security-officer',
    notes: ''
  });

  const loadReviews = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await DashboardService.getGovernanceReviews({}, apiKey);
      setReviews(res || []);
    } catch (err) {
      setError(err.message || 'Failed to load governance reviews');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadReviews();
  }, [apiKey]);

  const handleCreateReview = async (e) => {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);
    try {
      const created = await DashboardService.createGovernanceReview(formData, apiKey);
      setSuccessMsg(`Completed governance review ${created.review_id} (Score: ${created.overall_score.toFixed(1)}%)`);
      setShowModal(false);
      setFormData({
        review_type: 'CONTROL_EFFECTIVENESS',
        scope: 'enterprise',
        reviewer: 'security-officer',
        notes: ''
      });
      loadReviews();
    } catch (err) {
      setError(err.message || 'Failed to execute governance review');
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-emerald-950/60 border border-emerald-700/50 rounded-lg text-emerald-400">
            <ClipboardCheck className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              Security Governance Reviews & Audits
            </h2>
            <p className="text-xs text-slate-400">
              Periodic executive reviews validating posture, control effectiveness, and exception compliance
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded-lg transition"
          >
            <Plus className="w-4 h-4" />
            Conduct Review
          </button>
          <button
            onClick={loadReviews}
            disabled={loading}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded-lg transition border border-slate-700"
          >
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>

      {successMsg && (
        <div className="p-3 bg-emerald-950/50 border border-emerald-800 rounded-lg text-emerald-300 text-xs flex items-center gap-2">
          <CheckCircle className="w-4 h-4 text-emerald-400 flex-shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {error && (
        <div className="p-3 bg-rose-950/50 border border-rose-800 rounded-lg text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-rose-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Reviews List */}
      <div className="space-y-3">
        {reviews.length === 0 ? (
          <div className="p-8 text-center text-slate-500 border border-slate-800 rounded-lg">
            No governance reviews recorded yet. Click "Conduct Review" to perform an evaluation.
          </div>
        ) : (
          reviews.map((rev) => (
            <div
              key={rev.review_id}
              className="p-4 bg-slate-950/60 border border-slate-800 rounded-lg space-y-3 hover:border-slate-700 transition"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/60 pb-2.5">
                <div className="flex items-center space-x-2">
                  <span className="font-mono font-bold text-emerald-400 text-xs">{rev.review_id}</span>
                  <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-200 font-semibold">
                    {rev.review_type.replace(/_/g, ' ')}
                  </span>
                  <span className="text-xs text-slate-400 font-mono">[{rev.scope}]</span>
                </div>

                <div className="flex items-center space-x-3 text-xs text-slate-400">
                  <span className="flex items-center gap-1 font-mono">
                    <User className="w-3.5 h-3.5 text-slate-500" />
                    {rev.reviewer}
                  </span>
                  <span className="flex items-center gap-1 font-mono">
                    <Calendar className="w-3.5 h-3.5 text-slate-500" />
                    {new Date(rev.created_at).toLocaleDateString()}
                  </span>
                </div>
              </div>

              {/* Metrics Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-xs">
                <div className="p-2 bg-slate-900/60 rounded border border-slate-800/60">
                  <div className="text-slate-400 text-[10px]">Governance Score</div>
                  <div className="text-base font-bold text-slate-100 font-mono">
                    {rev.overall_score?.toFixed(1)}%
                  </div>
                </div>
                <div className="p-2 bg-slate-900/60 rounded border border-slate-800/60">
                  <div className="text-slate-400 text-[10px]">Control Coverage</div>
                  <div className="text-base font-bold text-slate-100 font-mono">
                    {rev.control_coverage?.toFixed(1)}%
                  </div>
                </div>
                <div className="p-2 bg-slate-900/60 rounded border border-slate-800/60">
                  <div className="text-slate-400 text-[10px]">Exceptions</div>
                  <div className="text-base font-bold text-slate-100 font-mono">
                    {rev.open_exceptions} <span className="text-xs font-normal text-rose-400">({rev.overdue_exceptions} overdue)</span>
                  </div>
                </div>
                <div className="p-2 bg-slate-900/60 rounded border border-slate-800/60">
                  <div className="text-slate-400 text-[10px]">Crit Exposures</div>
                  <div className="text-base font-bold text-rose-400 font-mono">
                    {rev.critical_exposures}
                  </div>
                </div>
                <div className="p-2 bg-slate-900/60 rounded border border-slate-800/60">
                  <div className="text-slate-400 text-[10px]">Active Incidents</div>
                  <div className="text-base font-bold text-amber-400 font-mono">
                    {rev.open_incidents}
                  </div>
                </div>
              </div>

              {/* Summary Narrative */}
              <div className="p-2.5 bg-slate-900/40 rounded border border-slate-800/40 text-xs text-slate-300">
                <span className="font-semibold text-slate-400">Executive Summary: </span>
                {rev.summary}
              </div>
            </div>
          ))
        )}
      </div>

      {/* Conduct Review Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-lg font-bold text-slate-100">Conduct Security Governance Review</h3>
            <form onSubmit={handleCreateReview} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Review Type *</label>
                <select
                  value={formData.review_type}
                  onChange={(e) => setFormData({ ...formData, review_type: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 text-slate-200 rounded-lg focus:outline-none focus:border-emerald-500"
                >
                  <option value="CONTROL_EFFECTIVENESS">CONTROL EFFECTIVENESS</option>
                  <option value="RISK_EXCEPTION_REVIEW">RISK EXCEPTION REVIEW</option>
                  <option value="EXPOSURE_REVIEW">EXPOSURE REVIEW</option>
                  <option value="INCIDENT_REVIEW">INCIDENT REVIEW</option>
                  <option value="EXECUTIVE_SECURITY_REVIEW">EXECUTIVE SECURITY REVIEW</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Scope</label>
                <input
                  type="text"
                  value={formData.scope}
                  onChange={(e) => setFormData({ ...formData, scope: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 text-slate-200 rounded-lg focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Reviewer</label>
                <input
                  type="text"
                  value={formData.reviewer}
                  onChange={(e) => setFormData({ ...formData, reviewer: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 text-slate-200 rounded-lg focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Notes / Scope Context</label>
                <textarea
                  rows="3"
                  value={formData.notes}
                  onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
                  placeholder="Optional review context or specific audit focus"
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 text-slate-200 rounded-lg focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-lg"
                >
                  Execute Review
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
