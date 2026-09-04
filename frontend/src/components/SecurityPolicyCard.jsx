import React, { useState } from 'react';
import { Sliders, ShieldCheck, Clock, CheckCircle2, RotateCcw, FileText, Check, AlertCircle } from 'lucide-react';
import { DashboardService } from '../services/dashboardApi';

export default function SecurityPolicyCard({ activePolicy, history, role, apiKey, onPolicyChanged }) {
  const [activatingVersion, setActivatingVersion] = useState(null);
  const [actionError, setActionError] = useState(null);
  const [actionSuccess, setActionSuccess] = useState(null);

  const isAdmin = role && role.toLowerCase() === 'admin';

  const handleActivate = async (version) => {
    if (!isAdmin) return;
    setActivatingVersion(version);
    setActionError(null);
    setActionSuccess(null);
    try {
      await DashboardService.activatePolicy(version, apiKey);
      setActionSuccess(`Policy version ${version} activated successfully.`);
      if (onPolicyChanged) {
        onPolicyChanged();
      }
    } catch (err) {
      setActionError(err.message || `Failed to activate policy version ${version}`);
    } finally {
      setActivatingVersion(null);
    }
  };

  if (!activePolicy) {
    return null;
  }

  const p = activePolicy.policy || {};
  const rateLimit = p.rate_limit || { requests: 10, window_seconds: 60 };
  const inputSec = p.input_security || { dlp_enabled: true, block_threshold: 60 };
  const respSec = p.response_security || { enabled: true, block_threshold: 80 };
  const cache = p.cache || { enabled: true, ttl_seconds: 300 };

  return (
    <div className="card security-policy-card" style={{ marginBottom: '24px' }}>
      <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
            <Sliders className="icon text-primary" size={20} />
            Centralized Security Policy Engine
          </h3>
          <p className="card-subtitle" style={{ margin: '4px 0 0 0', color: 'var(--text-muted)' }}>
            Active policy version <strong style={{ color: 'var(--text-primary)' }}>v{activePolicy.policy_version}</strong> • Updated by {activePolicy.updated_by}
          </p>
        </div>
        <span className="badge badge-success" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
          <ShieldCheck size={14} /> Active v{activePolicy.policy_version}
        </span>
      </div>

      {actionError && (
        <div className="error-banner" style={{ margin: '12px 0' }}>
          <AlertCircle size={16} />
          <span>{actionError}</span>
        </div>
      )}

      {actionSuccess && (
        <div className="success-banner" style={{ margin: '12px 0', padding: '10px 14px', background: 'rgba(34, 197, 94, 0.12)', border: '1px solid rgba(34, 197, 94, 0.3)', borderRadius: '6px', color: '#4ade80', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Check size={16} />
          <span>{actionSuccess}</span>
        </div>
      )}

      {/* Grid of active policy thresholds */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '14px', marginTop: '16px' }}>
        <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '12px 14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.07)' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', textTransform: 'uppercase' }}>Rate Limiting</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 700, marginTop: '4px', color: 'var(--text-primary)' }}>
            {rateLimit.requests} <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>req / {rateLimit.window_seconds}s</span>
          </div>
        </div>

        <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '12px 14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.07)' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', textTransform: 'uppercase' }}>Injection Block Threshold</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 700, marginTop: '4px', color: 'var(--danger)' }}>
            ≥ {inputSec.block_threshold} <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>risk score</span>
          </div>
        </div>

        <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '12px 14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.07)' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', textTransform: 'uppercase' }}>Response Block Threshold</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 700, marginTop: '4px', color: 'var(--warning)' }}>
            ≥ {respSec.block_threshold} <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>risk score</span>
          </div>
        </div>

        <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '12px 14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.07)' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', textTransform: 'uppercase' }}>Semantic Cache</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 700, marginTop: '4px', color: cache.enabled ? 'var(--success)' : 'var(--danger)' }}>
            {cache.enabled ? `Enabled (${cache.ttl_seconds}s)` : 'Disabled'}
          </div>
        </div>
      </div>

      {/* Policy Version History Table */}
      {history && history.length > 0 && (
        <div style={{ marginTop: '20px' }}>
          <div style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <FileText size={14} /> Version History & Rollback Registry
          </div>
          <div className="table-responsive" style={{ maxHeight: '180px', overflowY: 'auto' }}>
            <table className="data-table" style={{ width: '100%', fontSize: '0.85rem' }}>
              <thead>
                <tr>
                  <th>Version</th>
                  <th>Name</th>
                  <th>Status</th>
                  <th>Created By</th>
                  <th>Updated At</th>
                  {isAdmin && <th>Action</th>}
                </tr>
              </thead>
              <tbody>
                {history.map((item, idx) => (
                  <tr key={idx} style={{ background: item.is_active ? 'rgba(34, 197, 94, 0.05)' : 'transparent' }}>
                    <td><strong style={{ fontFamily: 'var(--font-mono)' }}>v{item.policy_version}</strong></td>
                    <td>{item.name}</td>
                    <td>
                      {item.is_active ? (
                        <span className="badge badge-success" style={{ fontSize: '11px' }}>Active</span>
                      ) : (
                        <span className="badge badge-neutral" style={{ fontSize: '11px' }}>Inactive</span>
                      )}
                    </td>
                    <td>{item.created_by}</td>
                    <td style={{ color: 'var(--text-muted)' }}>{new Date(item.updated_at).toLocaleString()}</td>
                    {isAdmin && (
                      <td>
                        {!item.is_active && (
                          <button
                            className="btn btn-sm btn-secondary"
                            onClick={() => handleActivate(item.policy_version)}
                            disabled={activatingVersion === item.policy_version}
                            style={{ padding: '3px 8px', fontSize: '12px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                          >
                            <RotateCcw size={12} />
                            {activatingVersion === item.policy_version ? 'Activating...' : 'Rollback / Activate'}
                          </button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
