import React from 'react';
import { Database, Zap, ArrowDownRight, Layers } from 'lucide-react';

export default function CacheStatsCard({ cacheStats }) {
  if (!cacheStats) return null;

  return (
    <div className="dashboard-panel" style={{ marginTop: '24px' }}>
      <div className="panel-header">
        <h2 className="panel-title">
          <Database size={18} style={{ color: 'var(--accent-cyan)' }} />
          Redis Semantic Cache Performance
        </h2>
        <span style={{
          fontSize: '11px',
          fontWeight: 600,
          padding: '2px 8px',
          borderRadius: '4px',
          background: cacheStats.enabled ? 'var(--status-allow-bg)' : 'rgba(239, 68, 68, 0.1)',
          color: cacheStats.enabled ? 'var(--status-allow)' : 'var(--status-block)',
          border: `1px solid ${cacheStats.enabled ? 'var(--status-allow-border)' : 'var(--status-block-border)'}`
        }}>
          {cacheStats.enabled ? 'CACHE ACTIVE' : 'CACHE DISABLED'}
        </span>
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
        gap: '16px'
      }}>
        <div style={{ background: 'var(--bg-card-subtle)', padding: '16px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', fontSize: '12px', marginBottom: '8px' }}>
            <span>Cache Hits</span>
            <Zap size={16} style={{ color: 'var(--status-allow)' }} />
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--status-allow)' }}>
            {cacheStats.hits.toLocaleString()}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            Zero upstream provider cost
          </div>
        </div>

        <div style={{ background: 'var(--bg-card-subtle)', padding: '16px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', fontSize: '12px', marginBottom: '8px' }}>
            <span>Cache Misses</span>
            <Layers size={16} style={{ color: 'var(--text-secondary)' }} />
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#ffffff' }}>
            {cacheStats.misses.toLocaleString()}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            Fresh upstream generation
          </div>
        </div>

        <div style={{ background: 'var(--bg-card-subtle)', padding: '16px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', fontSize: '12px', marginBottom: '8px' }}>
            <span>Hit Rate</span>
            <ArrowDownRight size={16} style={{ color: 'var(--accent-cyan)' }} />
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
            {cacheStats.hit_rate}%
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            From {cacheStats.total_cache_requests.toLocaleString()} eligible queries
          </div>
        </div>
      </div>
    </div>
  );
}
