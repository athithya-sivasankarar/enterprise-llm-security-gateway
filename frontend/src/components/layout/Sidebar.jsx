import React from 'react';
import { NavLink, Link } from 'react-router-dom';
import {
  LayoutDashboard,
  MessageSquare,
  Shield,
  History,
  FlaskConical,
  Target,
  ListOrdered,
  AlertOctagon,
  BellRing,
  AlertTriangle,
  Clock,
  Boxes,
  Globe2,
  FileText,
  Scale,
  ShieldAlert,
  Users,
  Sliders,
  Activity,
  ShieldCheck
} from 'lucide-react';

export const NAV_SECTIONS = [
  {
    title: 'OVERVIEW',
    items: [
      { path: '/', label: 'Dashboard', icon: LayoutDashboard, exact: true, badge: null }
    ]
  },
  {
    title: 'AI GATEWAY',
    items: [
      { path: '/gateway', label: 'Chat / Gateway', icon: MessageSquare, exact: true, badge: 'Live' },
      { path: '/gateway/controls', label: 'Security Controls', icon: ShieldCheck, exact: false, badge: '14' },
      { path: '/gateway/events', label: 'Security Events', icon: History, exact: false, badge: null }
    ]
  },
  {
    title: 'SECURITY TESTING',
    items: [
      { path: '/testing/catalog', label: 'Test Catalog', icon: FlaskConical, exact: false, badge: '26' },
      { path: '/testing/campaigns', label: 'Campaigns', icon: Target, exact: false, badge: null },
      { path: '/testing/runs', label: 'Test Runs', icon: ListOrdered, exact: false, badge: null },
      { path: '/testing/findings', label: 'Findings', icon: AlertOctagon, exact: false, badge: null }
    ]
  },
  {
    title: 'SOC',
    items: [
      { path: '/soc/alerts', label: 'Alerts', icon: BellRing, exact: false, badge: null },
      { path: '/soc/incidents', label: 'Incidents', icon: AlertTriangle, exact: false, badge: null }
    ]
  },
  {
    title: 'MONITORING',
    items: [
      { path: '/monitoring/scheduler', label: 'Scheduler', icon: Clock, exact: false, badge: null },
      { path: '/monitoring/assets', label: 'Assets', icon: Boxes, exact: false, badge: null },
      { path: '/monitoring/threat-intel', label: 'Threat Intelligence', icon: Globe2, exact: false, badge: null }
    ]
  },
  {
    title: 'COMPLIANCE',
    items: [
      { path: '/compliance/reports', label: 'Reports', icon: FileText, exact: false, badge: null },
      { path: '/compliance/governance', label: 'Governance', icon: Scale, exact: false, badge: null },
      { path: '/compliance/exceptions', label: 'Risk Exceptions', icon: ShieldAlert, exact: false, badge: null }
    ]
  },
  {
    title: 'ADMINISTRATION',
    items: [
      { path: '/admin/users', label: 'Users & RBAC', icon: Users, exact: false, badge: null },
      { path: '/admin/policies', label: 'Policies', icon: Sliders, exact: false, badge: null },
      { path: '/admin/system-health', label: 'System / Provider Health', icon: Activity, exact: false, badge: null }
    ]
  }
];

export default function Sidebar({ alertCount = 0, incidentCount = 0 }) {
  return (
    <aside className="app-sidebar">
      {/* Brand Header */}
      <Link to="/" className="sidebar-brand text-decoration-none">
        <div className="brand-logo-glow">
          <Shield size={22} className="brand-shield-icon" />
        </div>
        <div className="brand-text">
          <div className="brand-title">ENTERPRISE AI SECURITY</div>
          <div className="brand-sub">LLM Gateway & SOC Platform</div>
        </div>
      </Link>

      {/* Navigation Sections */}
      <nav className="sidebar-nav">
        {NAV_SECTIONS.map((section) => (
          <div key={section.title} className="nav-group">
            <div className="nav-group-title">{section.title}</div>
            <div className="nav-group-items">
              {section.items.map((item) => {
                const Icon = item.icon;
                
                let displayBadge = item.badge;
                let badgeClass = 'nav-badge';
                if (item.path === '/soc/alerts' && alertCount > 0) {
                  displayBadge = alertCount;
                  badgeClass = 'nav-badge nav-badge-danger';
                } else if (item.path === '/soc/incidents' && incidentCount > 0) {
                  displayBadge = incidentCount;
                  badgeClass = 'nav-badge nav-badge-warning';
                } else if (item.path === '/gateway') {
                  badgeClass = 'nav-badge nav-badge-live';
                }

                return (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    end={item.exact}
                    className={({ isActive }) =>
                      `nav-item text-decoration-none ${isActive ? 'nav-item-active' : ''}`
                    }
                    title={item.label}
                  >
                    <div className="nav-item-left">
                      <Icon size={17} className="nav-icon" />
                      <span className="nav-label">{item.label}</span>
                    </div>
                    {displayBadge && (
                      <span className={badgeClass}>{displayBadge}</span>
                    )}
                  </NavLink>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Sidebar Footer */}
      <div className="sidebar-footer">
        <div className="system-status-indicator">
          <span className="status-pulse-dot"></span>
          <div className="status-text">
            <span className="status-title">GATEWAY ENGINE</span>
            <span className="status-sub">Enforcing 14 Controls</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
