import React from 'react';
import { Cpu, Zap, ShieldAlert, Clock, CheckCircle, XCircle } from 'lucide-react';

export default function ProviderAnalytics({ providers = [], health = null }) {
  const providerHealthMap = health?.providers || {};

  return (
    <div className="dashboard-panel" style={{ marginTop: '24px' }}>
      <div className="panel-header">
        <h2 className="panel-title">
          <Cpu size={18} style={{ color: 'var(--accent-purple)' }} />
          Multi-Provider LLM Infrastructure
        </h2>
        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          {providers.length} Active Routing Layers
        </span>
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
        gap: '16px'
      }}>
        {['mock', 'openai', 'anthropic'].map((pName) => {
          const stat = providers.find(p => p.provider.toLowerCase() === pName) || {
            provider: pName,
            requests: 0,
            cache_hits: 0,
            blocked: 0,
            average_latency_ms: 0.0
          };
          const isConfigured = providerHealthMap[pName]?.configured ?? (pName === 'mock');

          const displayName = pName === 'openai' ? 'OpenAI (GPT-4o/o1)' :
                              pName === 'anthropic' ? 'Anthropic (Claude 3.5 Sonnet)' :
                              'Mock LLM (Simulation Engine)';

          return (
            <div
              key={pName}
              style={{
                background: 'var(--bg-card-subtle)',
                borderRadius: 'var(--radius-md)',
                border: '1px solid var(--border-subtle)',
                padding: '16px'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <div>
                  <div style={{ fontSize: '14px', fontWeight: 600, color: '#ffffff', textTransform: 'capitalize' }}>
                    {displayName}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    Provider ID: {pName}
                  </div>
                </div>

                <span style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px',
                  fontSize: '11px',
                  fontWeight: 600,
                  padding: '2px 8px',
                  borderRadius: '4px',
                  background: isConfigured ? 'var(--status-allow-bg)' : 'rgba(239, 68, 68, 0.1)',
                  color: isConfigured ? 'var(--status-allow)' : 'var(--status-block)',
                  border: `1px solid ${isConfigured ? 'var(--status-allow-border)' : 'var(--status-block-border)'}`
                }}>
                  {isConfigured ? <CheckCircle size={12} /> : <XCircle size={12} />}
                  {isConfigured ? 'CONFIGURED' : 'UNCONFIGURED'}
                </span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginTop: '12px' }}>
                <div style={{ background: 'rgba(0,0,0,0.2)', padding: '10px', borderRadius: '4px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Traffic Volume</div>
                  <div style={{ fontSize: '18px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#ffffff' }}>
                    {stat.requests.toLocaleString()} <span style={{ fontSize: '11px', fontWeight: 400, color: 'var(--text-muted)' }}>reqs</span>
                  </div>
                </div>

                <div style={{ background: 'rgba(0,0,0,0.2)', padding: '10px', borderRadius: '4px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Cache Hits</div>
                  <div style={{ fontSize: '18px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--status-allow)' }}>
                    {stat.cache_hits.toLocaleString()}
                  </div>
                </div>

                <div style={{ background: 'rgba(0,0,0,0.2)', padding: '10px', borderRadius: '4px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Security Blocks</div>
                  <div style={{ fontSize: '18px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: stat.blocked > 0 ? 'var(--status-block)' : 'var(--text-muted)' }}>
                    {stat.blocked.toLocaleString()}
                  </div>
                </div>

                <div style={{ background: 'rgba(0,0,0,0.2)', padding: '10px', borderRadius: '4px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Avg Latency</div>
                  <div style={{ fontSize: '18px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
                    {stat.average_latency_ms} <span style={{ fontSize: '10px', fontWeight: 400 }}>ms</span>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
