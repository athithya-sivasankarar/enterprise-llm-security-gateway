const API_BASE = '';

/**
 * Fetch wrapper handling X-API-Key authentication and error standardization
 */
async function fetchWithAuth(endpoint, apiKey, method = 'GET', body = null) {
  const headers = {
    'Content-Type': 'application/json',
    'X-API-Key': apiKey || 'dev-key-12345'
  };

  const options = { method, headers };
  if (body) {
    options.body = JSON.stringify(body);
  }

  const response = await fetch(`${API_BASE}${endpoint}`, options);
  if (!response.ok) {
    let errorDetail = `Request failed with status ${response.status}`;
    try {
      const data = await response.json();
      if (data.detail) {
        errorDetail = typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail);
      }
    } catch {
      // ignore
    }
    throw new Error(errorDetail);
  }

  return await response.json();
}

export const DashboardService = {
  sendChatMessage: async (data, apiKey) => {
    const headers = {
      'Content-Type': 'application/json',
      'X-API-Key': apiKey || 'dev-key-12345'
    };
    const response = await fetch(`${API_BASE}/api/chat`, {
      method: 'POST',
      headers,
      body: JSON.stringify(data)
    });
    const requestId = response.headers.get('X-Request-ID');
    const result = await response.json().catch(() => ({}));
    return {
      status: response.status,
      ok: response.ok,
      headers: { 'x-request-id': requestId },
      data: result
    };
  },
  getUserPermissions: (apiKey) => fetchWithAuth('/api/auth/me', apiKey),
  getSummary: (apiKey) => fetchWithAuth('/api/dashboard/summary', apiKey),
  getThreats: (apiKey) => fetchWithAuth('/api/dashboard/threats', apiKey),
  getRecentEvents: (apiKey, limit = 20) => fetchWithAuth(`/api/dashboard/recent-events?limit=${limit}`, apiKey),
  getModels: (apiKey) => fetchWithAuth('/api/dashboard/models', apiKey),
  getUsers: (apiKey) => fetchWithAuth('/api/dashboard/users', apiKey),
  getTimeline: (apiKey) => fetchWithAuth('/api/dashboard/timeline', apiKey),
  getCacheStats: (apiKey) => fetchWithAuth('/api/dashboard/cache', apiKey),
  getProviders: (apiKey) => fetchWithAuth('/api/dashboard/providers', apiKey),
  getProvidersHealth: () => fetch(`${API_BASE}/api/providers/health`).then(r => r.json()),
  getObservability: (apiKey) => fetchWithAuth('/api/dashboard/observability', apiKey),
  getSecurityEvents: (apiKey, limit = 50) => fetchWithAuth(`/api/security/events?limit=${limit}`, apiKey),
  getActivePolicy: (apiKey) => fetchWithAuth('/api/policies/active', apiKey),
  getPolicyHistory: (apiKey) => fetchWithAuth('/api/policies/history', apiKey),
  validatePolicy: (policyData, apiKey) => fetchWithAuth('/api/policies/validate', apiKey, 'POST', policyData),
  activatePolicy: (policyVersion, apiKey) => fetchWithAuth(`/api/policies/${policyVersion}/activate`, apiKey, 'POST'),
  getSecurityTestRuns: (apiKey) => fetchWithAuth('/api/security-tests/runs', apiKey),
  getSecurityTestReport: (runId, apiKey) => fetchWithAuth(`/api/security-tests/runs/${runId}/report`, apiKey),
  getSecurityFindings: (apiKey) => fetchWithAuth('/api/security-tests/findings', apiKey),
  getSecurityCatalog: (apiKey) => fetchWithAuth('/api/security-tests/catalog', apiKey),
  runSecurityTests: (payload, apiKey) => fetchWithAuth('/api/security-tests/run', apiKey, 'POST', payload),

  // Security Assessment Campaigns & Regression Detection
  getCampaigns: (apiKey, status = null) => fetchWithAuth(`/api/campaigns${status ? `?status=${status}` : ''}`, apiKey),
  getCampaign: (campaignId, apiKey) => fetchWithAuth(`/api/campaigns/${campaignId}`, apiKey),
  createCampaign: (data, apiKey) => fetchWithAuth('/api/campaigns', apiKey, 'POST', data),
  updateCampaign: (campaignId, data, apiKey) => fetchWithAuth(`/api/campaigns/${campaignId}`, apiKey, 'PUT', data),
  executeCampaign: (campaignId, apiKey) => fetchWithAuth(`/api/campaigns/${campaignId}/execute`, apiKey, 'POST'),
  getCampaignRuns: (campaignId, apiKey, limit = 20) => fetchWithAuth(`/api/campaigns/${campaignId}/runs?limit=${limit}`, apiKey),
  getCampaignRegressions: (campaignId, apiKey, limit = 50) => fetchWithAuth(`/api/campaigns/${campaignId}/regressions?limit=${limit}`, apiKey),
  setCampaignBaseline: (campaignId, runId, apiKey) => fetchWithAuth(`/api/campaigns/${campaignId}/baseline`, apiKey, 'POST', { run_id: runId }),
  pauseCampaign: (campaignId, apiKey) => fetchWithAuth(`/api/campaigns/${campaignId}/pause`, apiKey, 'POST'),
  resumeCampaign: (campaignId, apiKey) => fetchWithAuth(`/api/campaigns/${campaignId}/resume`, apiKey, 'POST'),
  archiveCampaign: (campaignId, apiKey) => fetchWithAuth(`/api/campaigns/${campaignId}/archive`, apiKey, 'POST'),

  // Step 17 — Continuous Security Posture, Scheduler & SOC Alerting
  getSecurityPosture: (apiKey) => fetchWithAuth('/api/dashboard/security-posture', apiKey),
  getSchedules: (apiKey) => fetchWithAuth('/api/scheduler/campaigns', apiKey),
  getSchedule: (campaignId, apiKey) => fetchWithAuth(`/api/scheduler/campaigns/${campaignId}`, apiKey),
  createSchedule: (campaignId, data, apiKey) => fetchWithAuth(`/api/scheduler/campaigns/${campaignId}`, apiKey, 'POST', data),
  updateSchedule: (campaignId, data, apiKey) => fetchWithAuth(`/api/scheduler/campaigns/${campaignId}`, apiKey, 'PUT', data),
  enableSchedule: (campaignId, apiKey) => fetchWithAuth(`/api/scheduler/campaigns/${campaignId}/enable`, apiKey, 'POST'),
  disableSchedule: (campaignId, apiKey) => fetchWithAuth(`/api/scheduler/campaigns/${campaignId}/disable`, apiKey, 'POST'),
  deleteSchedule: (campaignId, apiKey) => fetchWithAuth(`/api/scheduler/campaigns/${campaignId}`, apiKey, 'DELETE'),
  getSchedulerStatus: (apiKey) => fetchWithAuth('/api/scheduler/status', apiKey),
  getNextRuns: (apiKey) => fetchWithAuth('/api/scheduler/next-runs', apiKey),
  triggerScheduledCampaign: (campaignId, apiKey) => fetchWithAuth(`/api/scheduler/campaigns/${campaignId}/trigger`, apiKey, 'POST'),

  // SOC Alerts
  getAlerts: (apiKey, status = null, severity = null, limit = 50) => {
    const params = new URLSearchParams();
    if (status) params.append('status', status);
    if (severity) params.append('severity', severity);
    params.append('limit', limit);
    return fetchWithAuth(`/api/alerts?${params.toString()}`, apiKey);
  },
  getAlertSummary: (apiKey) => fetchWithAuth('/api/alerts/summary', apiKey),
  getOpenAlerts: (apiKey, limit = 50) => fetchWithAuth(`/api/alerts/open?limit=${limit}`, apiKey),
  acknowledgeAlert: (alertId, apiKey) => fetchWithAuth(`/api/alerts/${alertId}/acknowledge`, apiKey, 'POST'),
  resolveAlert: (alertId, apiKey) => fetchWithAuth(`/api/alerts/${alertId}/resolve`, apiKey, 'POST'),


  // Step 18 Reporting & Evidence API Client Methods
  createReport: (reportData, apiKey) => fetchWithAuth('/api/reports', apiKey, 'POST', reportData),
  getReports: (params = {}, apiKey) => {
    const query = new URLSearchParams();
    if (params.report_type) query.append('report_type', params.report_type);
    if (params.status) query.append('status', params.status);
    if (params.limit) query.append('limit', params.limit);
    const qs = query.toString() ? `?${query.toString()}` : '';
    return fetchWithAuth(`/api/reports${qs}`, apiKey);
  },
  getReport: (reportId, apiKey) => fetchWithAuth(`/api/reports/${reportId}`, apiKey),
  generateReport: (reportId, apiKey) => fetchWithAuth(`/api/reports/${reportId}/generate`, apiKey, 'POST'),
  getReportEvidence: (reportId, limit = 100, apiKey) => fetchWithAuth(`/api/reports/${reportId}/evidence?limit=${limit}`, apiKey),
  verifyReport: (reportId, apiKey) => fetchWithAuth(`/api/reports/${reportId}/verify`, apiKey),
  deleteReport: (reportId, apiKey) => fetchWithAuth(`/api/reports/${reportId}`, apiKey, 'DELETE'),
  exportReportUrl: (reportId, format = 'json') => `/api/reports/${reportId}/export?format=${format}`,

  // Step 19 Incident Management & Case Investigation API Methods
  getIncidents: (params = {}, apiKey) => {
    const query = new URLSearchParams();
    if (params.status) query.append('status', params.status);
    if (params.severity) query.append('severity', params.severity);
    if (params.limit) query.append('limit', params.limit);
    const qs = query.toString() ? `?${query.toString()}` : '';
    return fetchWithAuth(`/api/incidents${qs}`, apiKey);
  },
  getIncidentSummary: (apiKey) => fetchWithAuth('/api/incidents/summary', apiKey),
  getIncident: (incidentId, apiKey) => fetchWithAuth(`/api/incidents/${incidentId}`, apiKey),
  createIncident: (incidentData, apiKey) => fetchWithAuth('/api/incidents', apiKey, 'POST', incidentData),
  updateIncident: (incidentId, data, apiKey) => fetchWithAuth(`/api/incidents/${incidentId}`, apiKey, 'PUT', data),
  assignIncident: (incidentId, assignedTo, apiKey) => fetchWithAuth(`/api/incidents/${incidentId}/assign`, apiKey, 'POST', { assigned_to: assignedTo }),
  changeIncidentStatus: (incidentId, status, reason = null, apiKey) => fetchWithAuth(`/api/incidents/${incidentId}/status`, apiKey, 'POST', { status, reason }),
  addIncidentNote: (incidentId, note, apiKey) => fetchWithAuth(`/api/incidents/${incidentId}/notes`, apiKey, 'POST', { note }),
  getIncidentTimeline: (incidentId, apiKey) => fetchWithAuth(`/api/incidents/${incidentId}/timeline`, apiKey),
  getIncidentEvidence: (incidentId, apiKey) => fetchWithAuth(`/api/incidents/${incidentId}/evidence`, apiKey),
  attachIncidentEvidence: (incidentId, data, apiKey) => fetchWithAuth(`/api/incidents/${incidentId}/evidence`, apiKey, 'POST', data),
  attachIncidentReport: (incidentId, reportId, apiKey) => fetchWithAuth(`/api/incidents/${incidentId}/reports`, apiKey, 'POST', { report_id: reportId }),
  recordIncidentAction: (incidentId, data, apiKey) => fetchWithAuth(`/api/incidents/${incidentId}/actions`, apiKey, 'POST', data),
  resolveIncident: (incidentId, reason = null, apiKey) => fetchWithAuth(`/api/incidents/${incidentId}/resolve`, apiKey, 'POST', { reason }),
  markIncidentFalsePositive: (incidentId, reason = null, apiKey) => fetchWithAuth(`/api/incidents/${incidentId}/false-positive`, apiKey, 'POST', { reason }),

  // Step 20 Threat Intelligence, Attack Surface & Control Coverage API Methods
  getAssets: (params = {}, apiKey) => {
    const query = new URLSearchParams();
    if (params.asset_type) query.append('asset_type', params.asset_type);
    if (params.criticality) query.append('criticality', params.criticality);
    if (params.status) query.append('status', params.status);
    const qs = query.toString() ? `?${query.toString()}` : '';
    return fetchWithAuth(`/api/assets${qs}`, apiKey);
  },
  getAsset: (assetId, apiKey) => fetchWithAuth(`/api/assets/${assetId}`, apiKey),
  getAssetSummary: (apiKey) => fetchWithAuth('/api/assets/summary', apiKey),
  getAttackSurface: (apiKey) => fetchWithAuth('/api/assets/attack-surface', apiKey),
  getAssetCoverage: (assetId, apiKey) => fetchWithAuth(`/api/assets/${assetId}/coverage`, apiKey),
  createAsset: (data, apiKey) => fetchWithAuth('/api/assets', apiKey, 'POST', data),
  updateAsset: (assetId, data, apiKey) => fetchWithAuth(`/api/assets/${assetId}`, apiKey, 'PUT', data),

  getControls: (params = {}, apiKey) => {
    const query = new URLSearchParams();
    if (params.domain) query.append('domain', params.domain);
    const qs = query.toString() ? `?${query.toString()}` : '';
    return fetchWithAuth(`/api/controls${qs}`, apiKey);
  },
  getControl: (controlId, apiKey) => fetchWithAuth(`/api/controls/${controlId}`, apiKey),
  getControlCoverage: (runId = null, apiKey) => {
    const qs = runId ? `?run_id=${runId}` : '';
    return fetchWithAuth(`/api/controls/coverage${qs}`, apiKey);
  },
  getControlGaps: (runId = null, apiKey) => {
    const qs = runId ? `?run_id=${runId}` : '';
    return fetchWithAuth(`/api/controls/gaps${qs}`, apiKey);
  },

  getThreatIntelligence: (params = {}, apiKey) => {
    const query = new URLSearchParams();
    if (params.category) query.append('category', params.category);
    if (params.indicator_type) query.append('indicator_type', params.indicator_type);
    if (params.severity) query.append('severity', params.severity);
    if (params.limit) query.append('limit', params.limit);
    const qs = query.toString() ? `?${query.toString()}` : '';
    return fetchWithAuth(`/api/threat-intelligence${qs}`, apiKey);
  },
  getThreatIntelSummary: (apiKey) => fetchWithAuth('/api/threat-intelligence/summary', apiKey),
  getThreatIntelItem: (intelId, apiKey) => fetchWithAuth(`/api/threat-intelligence/${intelId}`, apiKey),
  createThreatIntelligence: (data, apiKey) => fetchWithAuth('/api/threat-intelligence', apiKey, 'POST', data),
  matchThreatIntelligence: (data, apiKey) => fetchWithAuth('/api/threat-intelligence/match', apiKey, 'POST', data),

  getExposures: (params = {}, apiKey) => {
    const query = new URLSearchParams();
    if (params.status) query.append('status', params.status);
    if (params.severity) query.append('severity', params.severity);
    if (params.asset_id) query.append('asset_id', params.asset_id);
    if (params.category) query.append('category', params.category);
    const qs = query.toString() ? `?${query.toString()}` : '';
    return fetchWithAuth(`/api/exposures${qs}`, apiKey);
  },
  getExposure: (exposureId, apiKey) => fetchWithAuth(`/api/exposures/${exposureId}`, apiKey),
  getExposureSummary: (apiKey) => fetchWithAuth('/api/exposures/summary', apiKey),
  createExposure: (data, apiKey) => fetchWithAuth('/api/exposures', apiKey, 'POST', data),
  resolveExposure: (exposureId, reason = null, apiKey) => fetchWithAuth(`/api/exposures/${exposureId}/resolve`, apiKey, 'POST', { reason }),

  // Step 21 Security Governance, Risk Acceptance & Control Assurance API Methods
  getGovernanceSummary: (apiKey) => fetchWithAuth('/api/governance/summary', apiKey),
  getGovernanceRisk: (apiKey) => fetchWithAuth('/api/governance/risk', apiKey),
  getControlAssurance: (apiKey) => fetchWithAuth('/api/governance/assurance', apiKey),
  getControlAssuranceDetail: (controlId, apiKey) => fetchWithAuth(`/api/governance/assurance/${controlId}`, apiKey),
  runControlAssurance: (controlId = null, apiKey) => {
    const qs = controlId ? `?control_id=${controlId}` : '';
    return fetchWithAuth(`/api/governance/assurance/run${qs}`, apiKey, 'POST');
  },
  getRiskExceptions: (params = {}, apiKey) => {
    const query = new URLSearchParams();
    if (params.status) query.append('status', params.status);
    if (params.severity) query.append('severity', params.severity);
    if (params.owner) query.append('owner', params.owner);
    if (params.asset_id) query.append('asset_id', params.asset_id);
    if (params.control_id) query.append('control_id', params.control_id);
    if (params.limit) query.append('limit', params.limit);
    if (params.offset) query.append('offset', params.offset);
    const qs = query.toString() ? `?${query.toString()}` : '';
    return fetchWithAuth(`/api/governance/exceptions${qs}`, apiKey);
  },
  getOverdueExceptions: (apiKey) => fetchWithAuth('/api/governance/exceptions/overdue', apiKey),
  getRiskExceptionDetail: (exceptionId, apiKey) => fetchWithAuth(`/api/governance/exceptions/${exceptionId}`, apiKey),
  createRiskException: (data, apiKey) => fetchWithAuth('/api/governance/exceptions', apiKey, 'POST', data),
  updateRiskException: (exceptionId, data, apiKey) => fetchWithAuth(`/api/governance/exceptions/${exceptionId}`, apiKey, 'PUT', data),
  submitRiskException: (exceptionId, apiKey) => fetchWithAuth(`/api/governance/exceptions/${exceptionId}/submit`, apiKey, 'POST'),
  approveRiskException: (exceptionId, data, apiKey) => fetchWithAuth(`/api/governance/exceptions/${exceptionId}/approve`, apiKey, 'POST', data),
  rejectRiskException: (exceptionId, data, apiKey) => fetchWithAuth(`/api/governance/exceptions/${exceptionId}/reject`, apiKey, 'POST', data),
  renewRiskException: (exceptionId, data, apiKey) => fetchWithAuth(`/api/governance/exceptions/${exceptionId}/renew`, apiKey, 'POST', data),
  revokeRiskException: (exceptionId, data = {}, apiKey) => fetchWithAuth(`/api/governance/exceptions/${exceptionId}/revoke`, apiKey, 'POST', data),
  closeRiskException: (exceptionId, data = {}, apiKey) => fetchWithAuth(`/api/governance/exceptions/${exceptionId}/close`, apiKey, 'POST', data),
  getGovernanceReviews: (params = {}, apiKey) => {
    const query = new URLSearchParams();
    if (params.review_type) query.append('review_type', params.review_type);
    if (params.status) query.append('status', params.status);
    if (params.limit) query.append('limit', params.limit);
    const qs = query.toString() ? `?${query.toString()}` : '';
    return fetchWithAuth(`/api/governance/reviews${qs}`, apiKey);
  },
  getGovernanceReview: (reviewId, apiKey) => fetchWithAuth(`/api/governance/reviews/${reviewId}`, apiKey),
  createGovernanceReview: (data, apiKey) => fetchWithAuth('/api/governance/reviews', apiKey, 'POST', data),
  getGovernanceEvents: (params = {}, apiKey) => {
    const query = new URLSearchParams();
    if (params.event_type) query.append('event_type', params.event_type);
    if (params.entity_type) query.append('entity_type', params.entity_type);
    if (params.limit) query.append('limit', params.limit);
    const qs = query.toString() ? `?${query.toString()}` : '';
    return fetchWithAuth(`/api/governance/events${qs}`, apiKey);
  }
};

export const dashboardApi = DashboardService;
export default DashboardService;







