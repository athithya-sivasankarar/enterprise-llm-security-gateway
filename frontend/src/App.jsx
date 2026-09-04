import React, { useState, useEffect, useCallback } from 'react';
import { Routes, Route, Navigate, Link } from 'react-router-dom';
import Sidebar from './components/layout/Sidebar';
import TopBar from './components/layout/TopBar';

// Dedicated Pages
import DashboardPage from './pages/DashboardPage';
import ChatGatewayPage from './pages/ChatGatewayPage';
import SecurityControlsPage from './pages/SecurityControlsPage';
import SecurityEventsPage from './pages/SecurityEventsPage';
import TestCatalogPage from './pages/TestCatalogPage';
import CampaignsPage from './pages/CampaignsPage';
import TestRunsPage from './pages/TestRunsPage';
import FindingsPage from './pages/FindingsPage';
import AlertsPage from './pages/AlertsPage';
import IncidentsPage from './pages/IncidentsPage';
import SchedulerPage from './pages/SchedulerPage';
import AssetsPage from './pages/AssetsPage';
import ThreatIntelPage from './pages/ThreatIntelPage';
import ReportsPage from './pages/ReportsPage';
import GovernancePage from './pages/GovernancePage';
import RiskExceptionsPage from './pages/RiskExceptionsPage';
import UsersRbacPage from './pages/UsersRbacPage';
import PoliciesPage from './pages/PoliciesPage';
import SystemHealthPage from './pages/SystemHealthPage';

import { DashboardService } from './services/dashboardApi';
import { AlertCircle, ShieldAlert } from 'lucide-react';

export default function App() {
  const [apiKey, setApiKey] = useState('dev-key-12345');
  const [permissions, setPermissions] = useState(null);
  const [error, setError] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Live badge counts for Sidebar
  const [openAlertsCount, setOpenAlertsCount] = useState(0);
  const [openIncidentsCount, setOpenIncidentsCount] = useState(0);

  const loadData = useCallback(async () => {
    setIsRefreshing(true);
    setError(null);
    try {
      const permRes = await DashboardService.getUserPermissions(apiKey);
      setPermissions(permRes);

      if (permRes.dashboard_access) {
        const [alertSum, incSum] = await Promise.all([
          DashboardService.getAlertSummary(apiKey).catch(() => null),
          DashboardService.getIncidentSummary(apiKey).catch(() => null)
        ]);

        if (alertSum) {
          setOpenAlertsCount(alertSum.open_alerts ?? 0);
        }
        if (incSum) {
          setOpenIncidentsCount(incSum.open_incidents ?? incSum.total_incidents ?? 0);
        }
      }
    } catch (err) {
      setError(err.message || 'Failed to connect to Security Gateway');
    } finally {
      setIsRefreshing(false);
    }
  }, [apiKey]);

  useEffect(() => {
    loadData();
    let timer;
    if (autoRefresh) {
      timer = setInterval(loadData, 10000);
    }
    return () => clearInterval(timer);
  }, [loadData, autoRefresh]);

  // Protected route wrapper for SOC analytics
  const ProtectedRoute = ({ children }) => {
    if (permissions && !permissions.dashboard_access) {
      return (
        <div className="rbac-restricted-container">
          <div className="rbac-restricted-card">
            <div className="rbac-icon-circle">
              <ShieldAlert size={32} />
            </div>

            <h2 className="text-xl font-bold mb-2">Access Restricted (RBAC Policy)</h2>

            <p className="text-secondary text-sm leading-relaxed mb-4">
              Your authenticated role (<strong className="text-white">{permissions.role}</strong>) does not have permission to access Security Operations Center analytics or testing suites.
              You can still test live prompts on the <strong>Chat / Gateway</strong> console, or switch to an <strong>Admin</strong> or <strong>Security Analyst</strong> persona in the top navigation.
            </p>

            <div className="d-flex justify-content-center gap-3">
              <Link to="/gateway" className="btn btn-primary text-decoration-none">
                Open LLM Gateway Console
              </Link>
              <button
                className="btn btn-outline"
                onClick={() => setApiKey('dev-key-12345')}
              >
                Switch to Admin Persona
              </button>
            </div>
          </div>
        </div>
      );
    }
    return children;
  };

  return (
    <div className="app-shell-layout">
      {/* 1. PERSISTENT SIDEBAR NAVIGATION */}
      <Sidebar
        alertCount={openAlertsCount}
        incidentCount={openIncidentsCount}
      />

      {/* 2. MAIN APPLICATION CONTENT AREA */}
      <div className="app-main-wrapper">
        {/* PERSISTENT TOP BAR */}
        <TopBar
          apiKey={apiKey}
          setApiKey={setApiKey}
          permissions={permissions}
          onRefresh={loadData}
          isRefreshing={isRefreshing}
          autoRefresh={autoRefresh}
          setAutoRefresh={setAutoRefresh}
        />

        {error && (
          <div className="error-banner m-4">
            <AlertCircle size={18} />
            <span>{error}</span>
          </div>
        )}

        {/* 3. STRICT ROUTE-BASED RENDERING (ONE PAGE AT A TIME) */}
        <main className="app-page-container">
          <Routes>
            {/* OVERVIEW */}
            <Route
              path="/"
              element={
                <ProtectedRoute>
                  <DashboardPage apiKey={apiKey} permissions={permissions} />
                </ProtectedRoute>
              }
            />

            {/* AI GATEWAY */}
            <Route
              path="/gateway"
              element={<ChatGatewayPage apiKey={apiKey} permissions={permissions} />}
            />
            <Route
              path="/gateway/controls"
              element={
                <ProtectedRoute>
                  <SecurityControlsPage apiKey={apiKey} />
                </ProtectedRoute>
              }
            />
            <Route
              path="/gateway/events"
              element={
                <ProtectedRoute>
                  <SecurityEventsPage apiKey={apiKey} />
                </ProtectedRoute>
              }
            />

            {/* SECURITY TESTING */}
            <Route
              path="/testing/catalog"
              element={
                <ProtectedRoute>
                  <TestCatalogPage apiKey={apiKey} permissions={permissions} />
                </ProtectedRoute>
              }
            />
            <Route
              path="/testing/campaigns"
              element={
                <ProtectedRoute>
                  <CampaignsPage apiKey={apiKey} permissions={permissions} />
                </ProtectedRoute>
              }
            />
            <Route
              path="/testing/runs"
              element={
                <ProtectedRoute>
                  <TestRunsPage apiKey={apiKey} permissions={permissions} />
                </ProtectedRoute>
              }
            />
            <Route
              path="/testing/findings"
              element={
                <ProtectedRoute>
                  <FindingsPage apiKey={apiKey} permissions={permissions} />
                </ProtectedRoute>
              }
            />

            {/* SOC */}
            <Route
              path="/soc/alerts"
              element={
                <ProtectedRoute>
                  <AlertsPage apiKey={apiKey} permissions={permissions} />
                </ProtectedRoute>
              }
            />
            <Route
              path="/soc/incidents"
              element={
                <ProtectedRoute>
                  <IncidentsPage apiKey={apiKey} permissions={permissions} />
                </ProtectedRoute>
              }
            />

            {/* MONITORING */}
            <Route
              path="/monitoring/scheduler"
              element={
                <ProtectedRoute>
                  <SchedulerPage apiKey={apiKey} permissions={permissions} />
                </ProtectedRoute>
              }
            />
            <Route
              path="/monitoring/assets"
              element={
                <ProtectedRoute>
                  <AssetsPage apiKey={apiKey} permissions={permissions} />
                </ProtectedRoute>
              }
            />
            <Route
              path="/monitoring/threat-intel"
              element={
                <ProtectedRoute>
                  <ThreatIntelPage apiKey={apiKey} permissions={permissions} />
                </ProtectedRoute>
              }
            />

            {/* COMPLIANCE */}
            <Route
              path="/compliance/reports"
              element={
                <ProtectedRoute>
                  <ReportsPage apiKey={apiKey} permissions={permissions} />
                </ProtectedRoute>
              }
            />
            <Route
              path="/compliance/governance"
              element={
                <ProtectedRoute>
                  <GovernancePage apiKey={apiKey} permissions={permissions} />
                </ProtectedRoute>
              }
            />
            <Route
              path="/compliance/exceptions"
              element={
                <ProtectedRoute>
                  <RiskExceptionsPage apiKey={apiKey} permissions={permissions} />
                </ProtectedRoute>
              }
            />

            {/* ADMINISTRATION */}
            <Route
              path="/admin/users"
              element={<UsersRbacPage apiKey={apiKey} permissions={permissions} />}
            />
            <Route
              path="/admin/policies"
              element={
                <ProtectedRoute>
                  <PoliciesPage apiKey={apiKey} permissions={permissions} />
                </ProtectedRoute>
              }
            />
            <Route
              path="/admin/system-health"
              element={
                <ProtectedRoute>
                  <SystemHealthPage apiKey={apiKey} permissions={permissions} />
                </ProtectedRoute>
              }
            />

            {/* Fallback route */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
