import React from 'react';
import { Activity, Gauge, AlertTriangle, ShieldCheck, Zap, ServerCrash, Clock, Database, Radio } from 'lucide-react';

export default function ObservabilityCard({ data, loading }) {
  if (loading && !data) {
    return (
      <div className="card loading-placeholder">
        <div className="skeleton-line" style={{ width: '40%' }}></div>
        <div className="skeleton-grid"></div>
      </div>
    );
  }

  const obs = data || {
    requests_per_minute: 0,
    error_rate: 0,
    blocked_requests: 0,
    pii_detections: 0,
    prompt_injections: 0,
    response_blocks: 0,
    provider_errors: 0,
    cache_hit_rate: 0,
    average_latency_ms: 0,
    p95_latency_ms: 0
  };

  return (
    <div className="card observability-card">
      <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
            <Activity className="icon text-primary" size={20} />
            Enterprise Observability & Telemetry
          </h3>
          <p className="card-subtitle" style={{ margin: '4px 0 0 0', color: 'var(--text-muted)' }}>
            Real-time Prometheus metrics, P95 latency distributions, and SIEM security signals
          </p>
        </div>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span className="badge badge-success" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
            <Radio size={12} className="animate-pulse" /> Prometheus /metrics Live
          </span>
        </div>
      </div>

      <div className="observability-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px', marginTop: '16px' }}>
        <div className="obs-stat-box" style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '16px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.07)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
            <Clock size={16} className="text-info" />
            <span>P95 Latency</span>
          </div>
          <div style={{ fontSize: '1.6rem', fontWeight: '700', marginTop: '6px', color: 'var(--text-primary)' }}>
            {obs.p95_latency_ms} <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>ms</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Avg: {obs.average_latency_ms} ms
          </div>
        </div>

        <div className="obs-stat-box" style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '16px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.07)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
            <AlertTriangle size={16} className={obs.error_rate > 5 ? "text-danger" : "text-success"} />
            <span>Error / Block Rate</span>
          </div>
          <div style={{ fontSize: '1.6rem', fontWeight: '700', marginTop: '6px', color: obs.error_rate > 5 ? "var(--danger)" : "var(--success)" }}>
            {obs.error_rate}%
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            {obs.blocked_requests} blocked requests
          </div>
        </div>

        <div className="obs-stat-box" style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '16px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.07)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
            <Zap size={16} className="text-warning" />
            <span>Cache Hit Rate</span>
          </div>
          <div style={{ fontSize: '1.6rem', fontWeight: '700', marginTop: '6px', color: 'var(--warning)' }}>
            {obs.cache_hit_rate}%
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Redis semantic cache efficiency
          </div>
        </div>

        <div className="obs-stat-box" style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '16px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.07)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
            <ShieldCheck size={16} className="text-primary" />
            <span>Threat Detections</span>
          </div>
          <div style={{ fontSize: '1.6rem', fontWeight: '700', marginTop: '6px', color: 'var(--primary)' }}>
            {obs.prompt_injections + obs.response_blocks}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            {obs.prompt_injections} Injections • {obs.response_blocks} Resp Blocks
          </div>
        </div>
      </div>
    </div>
  );
}
