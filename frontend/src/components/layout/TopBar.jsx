import React from 'react';
import { useLocation } from 'react-router-dom';
import {
  Shield,
  RefreshCw,
  Key,
  UserCheck,
  ChevronRight
} from 'lucide-react';
import { NAV_SECTIONS } from './Sidebar';

export default function TopBar({
  apiKey,
  setApiKey,
  permissions,
  onRefresh,
  isRefreshing,
  autoRefresh,
  setAutoRefresh
}) {
  const location = useLocation();
  const currentPath = location.pathname;

  // Find current breadcrumb path from route
  let sectionTitle = 'Overview';
  let pageTitle = 'Dashboard';

  for (const sec of NAV_SECTIONS) {
    const found = sec.items.find((item) => item.path === currentPath);
    if (found) {
      sectionTitle = sec.title;
      pageTitle = found.label;
      break;
    }
  }

  // Handle nested or fallback paths
  if (!pageTitle || currentPath === '/') {
    sectionTitle = 'Overview';
    pageTitle = 'Dashboard';
  }

  return (
    <header className="app-topbar">
      {/* Left: Breadcrumbs reflecting current route */}
      <div className="topbar-breadcrumbs">
        <span className="breadcrumb-section">{sectionTitle}</span>
        <ChevronRight size={14} className="breadcrumb-separator" />
        <span className="breadcrumb-current">{pageTitle}</span>
      </div>

      {/* Right: Controls, Role, API Key switcher, Sync */}
      <div className="topbar-actions">
        {/* Live Security Status */}
        <div className="gateway-live-pill" title="Security Gateway Active">
          <span className="live-dot"></span>
          <span className="live-text">GATEWAY ONLINE</span>
        </div>

        {/* Authenticated Role */}
        {permissions && (
          <div className="user-role-badge" title={`Current Authenticated Role: ${permissions.role}`}>
            <UserCheck size={14} className={permissions.dashboard_access ? 'role-icon-allowed' : 'role-icon-restricted'} />
            <span>Role: <strong className="role-name">{permissions.role}</strong></span>
          </div>
        )}

        {/* API Key Selector */}
        <div className="api-key-wrapper">
          <Key size={14} className="api-key-icon" />
          <select
            className="api-key-dropdown"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            title="Switch authenticated persona / API Key"
          >
            <option value="dev-key-12345">dev-key-12345 (Admin)</option>
            <option value="test-key-67890">test-key-67890 (Security Analyst)</option>
            <option value="dev-user-key-54321">dev-user-key-54321 (Developer)</option>
          </select>
        </div>

        {/* Auto Refresh Toggle */}
        <label className="auto-refresh-toggle" title="Automatically poll real-time telemetry every 10 seconds">
          <input
            type="checkbox"
            checked={autoRefresh}
            onChange={(e) => setAutoRefresh(e.target.checked)}
          />
          <span>Auto-sync (10s)</span>
        </label>

        {/* Refresh Button */}
        <button
          className="btn-sync"
          onClick={onRefresh}
          disabled={isRefreshing}
          title="Manual Telemetry Refresh"
        >
          <RefreshCw size={13} className={isRefreshing ? 'spin-icon' : ''} />
          <span>{isRefreshing ? 'Syncing...' : 'Sync'}</span>
        </button>
      </div>
    </header>
  );
}
