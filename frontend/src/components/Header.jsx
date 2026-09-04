import React from 'react';
import { Shield, RefreshCw, Key, UserCheck } from 'lucide-react';

export default function Header({
  apiKey,
  setApiKey,
  permissions,
  onRefresh,
  isRefreshing,
  autoRefresh,
  setAutoRefresh
}) {
  return (
    <header className="soc-header">
      <div className="brand-section">
        <div className="brand-icon">
          <Shield size={24} />
        </div>
        <div>
          <h1 className="brand-title">ENTERPRISE AI SECURITY</h1>
          <div className="brand-subtitle">Security Operations Center (SOC)</div>
        </div>
      </div>

      <div className="controls-section">
        <div className="status-indicator">
          <span className="status-dot"></span>
          <span>SYSTEM LIVE</span>
        </div>

        {permissions && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            padding: '6px 12px',
            borderRadius: 'var(--radius-sm)',
            fontSize: '12px',
            color: 'var(--text-secondary)'
          }}>
            <UserCheck size={14} style={{ color: permissions.dashboard_access ? 'var(--status-allow)' : 'var(--status-block)' }} />
            <span>Role: <strong style={{ color: '#fff', textTransform: 'capitalize' }}>{permissions.role}</strong></span>
          </div>
        )}

        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <Key size={16} style={{ color: 'var(--text-muted)' }} />
          <select
            className="api-key-select"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
          >
            <option value="dev-key-12345">dev-key-12345 (Admin)</option>
            <option value="test-key-67890">test-key-67890 (Analyst)</option>
            <option value="dev-user-key-54321">dev-user-key-54321 (Developer)</option>
          </select>
        </div>

        <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: 'var(--text-secondary)', cursor: 'pointer' }}>
          <input
            type="checkbox"
            checked={autoRefresh}
            onChange={(e) => setAutoRefresh(e.target.checked)}
            style={{ cursor: 'pointer' }}
          />
          Auto-refresh (30s)
        </label>

        <button
          className="btn btn-primary"
          onClick={onRefresh}
          disabled={isRefreshing}
        >
          <RefreshCw size={14} className={isRefreshing ? 'spin' : ''} />
          <span>{isRefreshing ? 'Syncing...' : 'Refresh'}</span>
        </button>
      </div>
    </header>
  );
}
