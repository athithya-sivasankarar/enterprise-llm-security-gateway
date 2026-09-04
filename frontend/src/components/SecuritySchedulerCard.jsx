import React, { useState, useEffect } from 'react';
import { dashboardApi } from '../services/dashboardApi';

export default function SecuritySchedulerCard({ apiKey }) {
  const [schedules, setSchedules] = useState([]);
  const [campaigns, setCampaigns] = useState([]);
  const [statusInfo, setStatusInfo] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [actionMsg, setActionMsg] = useState(null);

  // Modal State
  const [showModal, setShowModal] = useState(false);
  const [selectedCampaign, setSelectedCampaign] = useState('');
  const [scheduleType, setScheduleType] = useState('INTERVAL');
  const [intervalPreset, setIntervalPreset] = useState('1440');
  const [customInterval, setCustomInterval] = useState('1440');
  const [cronExpression, setCronExpression] = useState('0 0 * * *');
  const [timezone, setTimezone] = useState('UTC');
  const [saving, setSaving] = useState(false);

  const loadData = async () => {
    if (!apiKey) return;
    setLoading(true);
    setError(null);
    try {
      const [schedList, campList, stat] = await Promise.all([
        dashboardApi.getSchedules(apiKey),
        dashboardApi.getCampaigns(apiKey),
        dashboardApi.getSchedulerStatus(apiKey)
      ]);
      setSchedules(schedList || []);
      setCampaigns(campList || []);
      setStatusInfo(stat || null);
      if (campList && campList.length > 0 && !selectedCampaign) {
        setSelectedCampaign(campList[0].campaign_id);
      }
    } catch (err) {
      setError(err.message || 'Failed to load scheduler data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, [apiKey]);

  const handleCreateSchedule = async (e) => {
    e.preventDefault();
    if (!selectedCampaign) {
      setError('Please select a campaign.');
      return;
    }

    setSaving(true);
    setError(null);
    try {
      const payload = {
        schedule_type: scheduleType,
        timezone: timezone,
        enabled: true
      };

      if (scheduleType === 'INTERVAL') {
        const mins = intervalPreset === 'custom' ? parseInt(customInterval, 10) : parseInt(intervalPreset, 10);
        if (isNaN(mins) || mins < 60) {
          setError('Interval must be an integer greater than or equal to 60 minutes.');
          setSaving(false);
          return;
        }
        payload.interval_minutes = mins;
      } else {
        if (!cronExpression) {
          setError('Cron expression is required.');
          setSaving(false);
          return;
        }
        payload.cron_expression = cronExpression.trim();
      }

      await dashboardApi.createSchedule(selectedCampaign, payload, apiKey);
      setActionMsg(`Successfully scheduled campaign '${selectedCampaign}'.`);
      setShowModal(false);
      await loadData();
    } catch (err) {
      setError(err.message || 'Failed to create schedule');
    } finally {
      setSaving(false);
    }
  };

  const handleToggleEnable = async (campaignId, currentlyEnabled) => {
    setError(null);
    try {
      if (currentlyEnabled) {
        await dashboardApi.disableSchedule(campaignId, apiKey);
        setActionMsg(`Disabled schedule for '${campaignId}'.`);
      } else {
        await dashboardApi.enableSchedule(campaignId, apiKey);
        setActionMsg(`Enabled schedule for '${campaignId}'.`);
      }
      await loadData();
    } catch (err) {
      setError(err.message || 'Failed to toggle schedule state');
    }
  };

  const handleTriggerNow = async (campaignId) => {
    setError(null);
    setActionMsg(`Triggering assessment run for campaign '${campaignId}'...`);
    try {
      const res = await dashboardApi.triggerScheduledCampaign(campaignId, apiKey);
      setActionMsg(`Assessment run '${res.run?.campaign_run_id}' completed (Score: ${res.run?.security_score}%).`);
      await loadData();
    } catch (err) {
      setError(err.message || 'Failed to trigger scheduled run');
    }
  };

  const handleDeleteSchedule = async (campaignId) => {
    if (!window.confirm(`Are you sure you want to delete the schedule for campaign '${campaignId}'?`)) return;
    setError(null);
    try {
      await dashboardApi.deleteSchedule(campaignId, apiKey);
      setActionMsg(`Deleted schedule for '${campaignId}'.`);
      await loadData();
    } catch (err) {
      setError(err.message || 'Failed to delete schedule');
    }
  };

  return (
    <div className="card mb-4">
      <div className="card-header d-flex justify-content-between align-items-center">
        <div>
          <h3 className="card-title mb-1">Automated Security Campaign Scheduler</h3>
          <span className="text-muted" style={{ fontSize: '0.85rem' }}>
            Continuous background execution of security validation campaigns (Min frequency: 60 min)
          </span>
        </div>
        <div className="d-flex align-items-center gap-2">
          {statusInfo && (
            <span className={`badge ${statusInfo.worker_running ? 'badge-success' : 'badge-secondary'}`}>
              {statusInfo.worker_running ? '● Scheduler Active' : '○ Worker Standby'}
            </span>
          )}
          <button className="btn btn-sm btn-primary" onClick={() => setShowModal(true)}>
            + Schedule Campaign
          </button>
          <button className="btn btn-sm btn-outline" onClick={loadData} title="Refresh Schedules">
            🔄
          </button>
        </div>
      </div>

      {actionMsg && (
        <div className="alert alert-info py-2 px-3 mb-3 d-flex justify-content-between align-items-center" style={{ fontSize: '0.85rem' }}>
          <span>ℹ️ {actionMsg}</span>
          <button className="btn-close" onClick={() => setActionMsg(null)}>×</button>
        </div>
      )}

      {error && (
        <div className="alert alert-danger py-2 px-3 mb-3 d-flex justify-content-between align-items-center" style={{ fontSize: '0.85rem' }}>
          <span>⚠️ {error}</span>
          <button className="btn-close" onClick={() => setError(null)}>×</button>
        </div>
      )}

      {loading && schedules.length === 0 ? (
        <div className="text-center py-4 text-muted">Loading schedules...</div>
      ) : schedules.length === 0 ? (
        <div className="text-center py-4 text-muted">
          No automated schedules configured yet. Click "+ Schedule Campaign" to create recurring security assessment runs.
        </div>
      ) : (
        <div className="table-responsive">
          <table className="table table-hover align-middle mb-0">
            <thead>
              <tr>
                <th>Campaign</th>
                <th>Schedule</th>
                <th>Next Run</th>
                <th>Last Run</th>
                <th>Status</th>
                <th>Enabled</th>
                <th className="text-end">Actions</th>
              </tr>
            </thead>
            <tbody>
              {schedules.map((s) => (
                <tr key={s.schedule_id}>
                  <td>
                    <div className="font-semibold">{s.campaign_id}</div>
                    <small className="text-muted">{s.timezone}</small>
                  </td>
                  <td>
                    <span className="badge badge-secondary mr-2">{s.schedule_type}</span>
                    <span style={{ fontSize: '0.85rem' }}>
                      {s.schedule_type === 'CRON' ? s.cron_expression : `Every ${s.interval_minutes} mins`}
                    </span>
                  </td>
                  <td>
                    {s.enabled && s.next_run_at ? (
                      <span className="text-info font-mono" style={{ fontSize: '0.85rem' }}>
                        {new Date(s.next_run_at).toLocaleString()}
                      </span>
                    ) : (
                      <span className="text-muted">—</span>
                    )}
                  </td>
                  <td>
                    {s.last_run_at ? (
                      <div>
                        <div style={{ fontSize: '0.8rem' }}>{new Date(s.last_run_at).toLocaleTimeString()}</div>
                        {s.last_run_status && (
                          <span className={`badge badge-sm ${s.last_run_status === 'COMPLETED' ? 'badge-success' : s.last_run_status === 'COMPLETED_WITH_REGRESSIONS' ? 'badge-warning' : 'badge-danger'}`}>
                            {s.last_run_status}
                          </span>
                        )}
                      </div>
                    ) : (
                      <span className="text-muted">Never</span>
                    )}
                  </td>
                  <td>
                    {s.last_error ? (
                      <span className="text-danger font-semibold" title={s.last_error} style={{ fontSize: '0.8rem' }}>
                        ⚠️ Error
                      </span>
                    ) : (
                      <span className="text-success" style={{ fontSize: '0.8rem' }}>✓ OK</span>
                    )}
                  </td>
                  <td>
                    <button
                      className={`btn btn-sm ${s.enabled ? 'btn-success' : 'btn-secondary'}`}
                      onClick={() => handleToggleEnable(s.campaign_id, s.enabled)}
                      style={{ fontSize: '0.75rem', padding: '2px 8px' }}
                    >
                      {s.enabled ? 'Active' : 'Disabled'}
                    </button>
                  </td>
                  <td className="text-end">
                    <div className="d-flex justify-content-end gap-1">
                      <button
                        className="btn btn-sm btn-outline-primary"
                        onClick={() => handleTriggerNow(s.campaign_id)}
                        title="Trigger immediate execution"
                        style={{ fontSize: '0.75rem' }}
                      >
                        ⚡ Run Now
                      </button>
                      <button
                        className="btn btn-sm btn-outline-danger"
                        onClick={() => handleDeleteSchedule(s.campaign_id)}
                        title="Delete schedule"
                        style={{ fontSize: '0.75rem' }}
                      >
                        🗑️
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Schedule Create Modal */}
      {showModal && (
        <div className="modal-backdrop d-flex justify-content-center align-items-center" style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.6)', zIndex: 1000 }}>
          <div className="card" style={{ width: '520px', maxWidth: '90%' }}>
            <div className="card-header d-flex justify-content-between align-items-center">
              <h4 className="mb-0">Configure Recurring Campaign Schedule</h4>
              <button className="btn-close" onClick={() => setShowModal(false)}>×</button>
            </div>
            <form onSubmit={handleCreateSchedule} className="p-3">
              <div className="mb-3">
                <label className="form-label font-semibold">Select Campaign</label>
                <select
                  className="form-select"
                  value={selectedCampaign}
                  onChange={(e) => setSelectedCampaign(e.target.value)}
                  required
                >
                  {campaigns.map((c) => (
                    <option key={c.campaign_id} value={c.campaign_id}>
                      {c.name} ({c.campaign_id}) - {c.status}
                    </option>
                  ))}
                </select>
              </div>

              <div className="mb-3">
                <label className="form-label font-semibold">Schedule Type</label>
                <div className="d-flex gap-3">
                  <label className="d-flex align-items-center gap-1">
                    <input
                      type="radio"
                      name="scheduleType"
                      value="INTERVAL"
                      checked={scheduleType === 'INTERVAL'}
                      onChange={() => setScheduleType('INTERVAL')}
                    />
                    Interval Schedule
                  </label>
                  <label className="d-flex align-items-center gap-1">
                    <input
                      type="radio"
                      name="scheduleType"
                      value="CRON"
                      checked={scheduleType === 'CRON'}
                      onChange={() => setScheduleType('CRON')}
                    />
                    Cron Expression
                  </label>
                </div>
              </div>

              {scheduleType === 'INTERVAL' ? (
                <div className="mb-3">
                  <label className="form-label font-semibold">Execution Frequency</label>
                  <select
                    className="form-select mb-2"
                    value={intervalPreset}
                    onChange={(e) => setIntervalPreset(e.target.value)}
                  >
                    <option value="60">Hourly (60 minutes)</option>
                    <option value="360">Every 6 Hours (360 minutes)</option>
                    <option value="1440">Daily (1440 minutes / 24 hours)</option>
                    <option value="10080">Weekly (10080 minutes / 7 days)</option>
                    <option value="custom">Custom Interval (Minutes)...</option>
                  </select>

                  {intervalPreset === 'custom' && (
                    <input
                      type="number"
                      className="form-control"
                      placeholder="Minimum 60 minutes"
                      min="60"
                      value={customInterval}
                      onChange={(e) => setCustomInterval(e.target.value)}
                      required
                    />
                  )}
                  <small className="text-muted d-block mt-1">
                    🛡️ Safety Policy: Execution frequency cannot be less than once every 60 minutes.
                  </small>
                </div>
              ) : (
                <div className="mb-3">
                  <label className="form-label font-semibold">Cron Expression (5 fields)</label>
                  <input
                    type="text"
                    className="form-control font-mono"
                    placeholder="0 0 * * *"
                    value={cronExpression}
                    onChange={(e) => setCronExpression(e.target.value)}
                    required
                  />
                  <div className="d-flex gap-2 mt-2">
                    <button type="button" className="btn btn-xs btn-outline" onClick={() => setCronExpression('0 * * * *')}>
                      Hourly (0 * * * *)
                    </button>
                    <button type="button" className="btn btn-xs btn-outline" onClick={() => setCronExpression('0 0 * * *')}>
                      Daily (0 0 * * *)
                    </button>
                    <button type="button" className="btn btn-xs btn-outline" onClick={() => setCronExpression('0 0 * * 0')}>
                      Weekly (0 0 * * 0)
                    </button>
                  </div>
                  <small className="text-muted d-block mt-1">
                    🛡️ Safety Policy: Expressions executing more frequently than hourly (e.g. * * * * *) are rejected.
                  </small>
                </div>
              )}

              <div className="mb-3">
                <label className="form-label font-semibold">Timezone</label>
                <input
                  type="text"
                  className="form-control"
                  value={timezone}
                  onChange={(e) => setTimezone(e.target.value)}
                  placeholder="UTC"
                />
              </div>

              <div className="d-flex justify-content-end gap-2 mt-4">
                <button type="button" className="btn btn-outline" onClick={() => setShowModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={saving}>
                  {saving ? 'Scheduling...' : 'Save Schedule'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
