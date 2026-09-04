import React from 'react';
import { Users } from 'lucide-react';

export default function UserAnalytics({ users }) {
  const userList = users || [];

  return (
    <div className="dashboard-panel" style={{ marginTop: '24px' }}>
      <div className="panel-header">
        <h2 className="panel-title">
          <Users size={18} style={{ color: 'var(--accent-indigo)' }} />
          User Activity & Violations
        </h2>
        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          {userList.length} Active Accounts
        </span>
      </div>

      {userList.length === 0 ? (
        <div className="empty-state">No user activity recorded yet.</div>
      ) : (
        <div className="events-table-wrapper">
          <table className="events-table">
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Total Requests</th>
                <th>Blocked Requests</th>
                <th>PII Detections</th>
                <th>Injection Detections</th>
              </tr>
            </thead>
            <tbody>
              {userList.map((u, idx) => (
                <tr key={idx}>
                  <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{u.user}</td>
                  <td>
                    <span className="badge" style={{ background: 'rgba(99, 102, 241, 0.1)', color: '#a5b4fc' }}>
                      {u.role}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{u.requests}</td>
                  <td>
                    {u.blocked > 0 ? (
                      <span className="badge badge-block">{u.blocked}</span>
                    ) : (
                      '0'
                    )}
                  </td>
                  <td>
                    {u.pii_detections > 0 ? (
                      <span className="badge badge-sanitize">{u.pii_detections}</span>
                    ) : (
                      '0'
                    )}
                  </td>
                  <td>
                    {u.injection_detections > 0 ? (
                      <span className="badge badge-block">{u.injection_detections}</span>
                    ) : (
                      '0'
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
