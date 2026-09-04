import React, { useState, useEffect } from 'react';
import PageHeader from '../components/layout/PageHeader';
import UserAnalytics from '../components/UserAnalytics';
import { Users, Shield, CheckCircle2, Lock, Key } from 'lucide-react';
import { DashboardService } from '../services/dashboardApi';

const PERSONAS = [
  {
    role: 'Admin',
    key: 'dev-key-12345',
    user: 'developer',
    dashboardAccess: true,
    allowedModels: ['mock-model', 'gpt-4o-mini', 'gpt-4', 'gpt-4o', 'claude-3-5-sonnet-latest', 'claude-3-haiku-20240307'],
    restrictedModels: [],
    permissions: ['Chat Gateway', 'Security Test Execution', 'Campaign Management', 'SOC Alerts & Incidents', 'Policy Activation', 'Audit Logs']
  },
  {
    role: 'Security Analyst',
    key: 'test-key-67890',
    user: 'security-analyst',
    dashboardAccess: true,
    allowedModels: ['mock-model', 'gpt-4o-mini', 'claude-3-5-sonnet-latest'],
    restrictedModels: ['gpt-4', 'gpt-4o', 'claude-3-haiku-20240307'],
    permissions: ['Chat Gateway', 'Security Test Execution', 'Campaign Management', 'SOC Alerts & Incidents', 'Audit Logs']
  },
  {
    role: 'App Developer',
    key: 'dev-user-key-54321',
    user: 'app-developer',
    dashboardAccess: false,
    allowedModels: ['mock-model'],
    restrictedModels: ['gpt-4o-mini', 'gpt-4', 'gpt-4o', 'claude-3-5-sonnet-latest', 'claude-3-haiku-20240307'],
    permissions: ['Chat Gateway (Mock Model Only)']
  }
];

export default function UsersRbacPage({ apiKey, permissions, onNavigate }) {
  const [usersData, setUsersData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        setLoading(true);
        const data = await DashboardService.getUsers(apiKey);
        setUsersData(data?.users || []);
      } catch (err) {
        console.error('Failed to load user analytics:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, [apiKey]);

  return (
    <div className="users-rbac-page">
      <PageHeader
        title="Users & Role-Based Access Control (RBAC)"
        subtitle="Role definitions, authorized LLM model access lists, and SOC dashboard telemetry permissions."
        helpText="RBAC enforces strict boundary separation: Developers can access sandbox models for app integration; Admins and Analysts have authorized access to SOC analytics and testing."
      />

      {/* RBAC ROLES & MODEL PERMISSIONS MATRIX */}
      <div className="card console-card mb-6">
        <div className="card-header">
          <span className="card-title font-semibold text-sm">Role-Based Model Permissions & Access Policy</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 p-4">
          {PERSONAS.map((p) => {
            const isCurrent = permissions?.role?.toLowerCase() === p.role.toLowerCase();

            return (
              <div
                key={p.role}
                className="bg-card-subtle p-4 rounded-xl border border-subtle d-flex flex-direction-column justify-content-between"
                style={{ borderColor: isCurrent ? 'var(--accent-blue)' : 'var(--border-subtle)' }}
              >
                <div>
                  <div className="d-flex justify-content-between align-items-center mb-2">
                    <span className="font-bold text-sm text-primary">{p.role}</span>
                    {isCurrent && <span className="badge badge-allow text-xxs">CURRENT USER</span>}
                  </div>

                  <div className="font-mono text-xxs text-muted mb-3 d-flex align-items-center gap-1">
                    <Key size={12} />
                    <span>API Key: {p.key}</span>
                  </div>

                  {/* Dashboard Access */}
                  <div className="mb-3 text-xs">
                    <span className="text-muted d-block text-xxs text-uppercase mb-1">SOC Dashboard Access</span>
                    <span className={`badge ${p.dashboardAccess ? 'badge-allow' : 'badge-block'}`}>
                      {p.dashboardAccess ? 'AUTHORIZED' : 'RESTRICTED (403)'}
                    </span>
                  </div>

                  {/* Allowed Models */}
                  <div className="mb-3 text-xs">
                    <span className="text-muted d-block text-xxs text-uppercase mb-1">Allowed Models</span>
                    <div className="d-flex flex-wrap gap-1">
                      {p.allowedModels.map((m) => (
                        <span key={m} className="badge badge-subtle font-mono text-xxs text-success">
                          ✓ {m}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Restricted Models */}
                  {p.restrictedModels.length > 0 && (
                    <div className="mb-3 text-xs">
                      <span className="text-muted d-block text-xxs text-uppercase mb-1">Blocked Models</span>
                      <div className="d-flex flex-wrap gap-1">
                        {p.restrictedModels.map((m) => (
                          <span key={m} className="badge badge-subtle font-mono text-xxs text-danger">
                            ✕ {m}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Permissions List */}
                <div className="pt-3 border-top border-subtle text-xxs text-muted">
                  <span className="font-semibold text-primary d-block mb-1">Assigned Capabilities:</span>
                  <ul className="pl-3 mb-0">
                    {p.permissions.map((perm, idx) => (
                      <li key={idx}>{perm}</li>
                    ))}
                  </ul>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* RECENT USER TRAFFIC TELEMETRY */}
      <UserAnalytics users={usersData} />
    </div>
  );
}
