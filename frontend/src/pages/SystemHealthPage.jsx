import React, { useState, useEffect } from 'react';
import PageHeader from '../components/layout/PageHeader';
import ProviderAnalytics from '../components/ProviderAnalytics';
import CacheStatsCard from '../components/CacheStatsCard';
import ObservabilityCard from '../components/ObservabilityCard';
import ModelUsage from '../components/ModelUsage';
import ThreatOverview from '../components/ThreatOverview';
import { Activity, Server, Database, RefreshCw, Layers } from 'lucide-react';
import { DashboardService } from '../services/dashboardApi';

export default function SystemHealthPage({ apiKey, permissions, onNavigate }) {
  const [providerHealth, setProviderHealth] = useState(null);
  const [providers, setProviders] = useState([]);
  const [cacheStats, setCacheStats] = useState(null);
  const [observability, setObservability] = useState(null);
  const [models, setModels] = useState([]);
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);

  const loadHealthData = async () => {
    try {
      setLoading(true);
      const [healthRes, provRes, cacheRes, obsRes, modelRes, threatRes] = await Promise.all([
        DashboardService.getProvidersHealth().catch(() => null),
        DashboardService.getProviders(apiKey).catch(() => ({ providers: [] })),
        DashboardService.getCacheStats(apiKey).catch(() => null),
        DashboardService.getObservability(apiKey).catch(() => null),
        DashboardService.getModels(apiKey).catch(() => ({ models: [] })),
        DashboardService.getThreats(apiKey).catch(() => ({ threats: [] }))
      ]);

      setProviderHealth(healthRes);
      setProviders(provRes?.providers || []);
      setCacheStats(cacheRes);
      setObservability(obsRes);
      setModels(modelRes?.models || []);
      setThreats(threatRes?.threats || []);
    } catch (err) {
      console.error('Failed loading system health metrics:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHealthData();
  }, [apiKey]);

  return (
    <div className="system-health-page">
      <PageHeader
        title="System Infrastructure & Provider Health"
        subtitle="Upstream LLM provider connectivity, tenant-isolated semantic cache metrics, and OpenTelemetry observability telemetry."
        helpText="Detect provider configuration state, upstream model response latencies, and cache hit rates across runtime gateway nodes."
        actions={
          <button className="btn btn-outline" onClick={loadHealthData} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'spin-icon' : ''} />
            <span>Refresh Telemetry</span>
          </button>
        }
      />

      {/* Provider Connectivity Analytics */}
      <div className="mb-6">
        <ProviderAnalytics providers={providers} health={providerHealth} />
      </div>

      {/* Semantic Cache Analytics */}
      {cacheStats && (
        <div className="mb-6">
          <CacheStatsCard cacheStats={cacheStats} />
        </div>
      )}

      {/* Observability & Prometheus Metrics */}
      <div className="mb-6">
        <ObservabilityCard data={observability} loading={loading} />
      </div>

      {/* Model Analytics & Threat Overview */}
      <div className="dashboard-grid">
        <ThreatOverview threats={threats} />
        <ModelUsage models={models} />
      </div>
    </div>
  );
}
