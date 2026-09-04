import React from 'react';
import { ListFilter, Shield } from 'lucide-react';

export default function RecentEventsTable({ events }) {
  const eventList = events || [];

  const formatTimestamp = (ts) => {
    try {
      const d = new Date(ts);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return ts;
    }
  };

  const getActionBadge = (action) => {
    switch (action) {
      case 'ALLOW':
        return <span className="badge badge-allow">ALLOW</span>;
      case 'SANITIZE':
        return <span className="badge badge-sanitize">SANITIZE</span>;
      case 'BLOCK':
        return <span className="badge badge-block">BLOCK</span>;
      default:
        return <span className="badge">{action}</span>;
    }
  };

  return (
    <div className="dashboard-panel" style={{ marginTop: '24px' }}>
      <div className="panel-header">
        <h2 className="panel-title">
          <ListFilter size={18} style={{ color: 'var(--accent-blue)' }} />
          Recent Security Events (Metadata Only)
        </h2>
        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          Showing latest {eventList.length} events
        </span>
      </div>

      {eventList.length === 0 ? (
        <div className="empty-state">No security events recorded yet.</div>
      ) : (
        <div className="events-table-wrapper">
          <table className="events-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Request ID</th>
                <th>User (Role)</th>
                <th>Model</th>
                <th>Action</th>
                <th>Risk</th>
                <th>Threat Type</th>
                <th>PII / Entities</th>
                <th>Status</th>
                <th>Latency</th>
              </tr>
            </thead>
            <tbody>
              {eventList.map((evt) => (
                <tr key={evt.request_id}>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                    {formatTimestamp(evt.timestamp)}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                    {evt.request_id.substring(0, 8)}...
                  </td>
                  <td>
                    <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{evt.user}</span>
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)', marginLeft: '4px' }}>({evt.role})</span>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{evt.model}</td>
                  <td>{getActionBadge(evt.action)}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: evt.risk_score >= 60 ? 'var(--status-block)' : 'inherit' }}>
                    {evt.risk_score}
                  </td>
                  <td>
                    {evt.threat_type || evt.response_threat_type ? (
                      <span className="badge badge-threat">
                        {evt.threat_type || evt.response_threat_type}
                      </span>
                    ) : (
                      <span style={{ color: 'var(--text-muted)' }}>—</span>
                    )}
                  </td>
                  <td>
                    {evt.detected_entities && evt.detected_entities.length > 0 ? (
                      <span style={{ fontSize: '11px', color: 'var(--status-sanitize)' }}>
                        {evt.detected_entities.join(', ')}
                      </span>
                    ) : (
                      <span style={{ color: 'var(--text-muted)' }}>—</span>
                    )}
                  </td>
                  <td>
                    <span style={{
                      fontFamily: 'var(--font-mono)',
                      color: evt.response_status === 200 ? 'var(--status-allow)' : 'var(--status-block)'
                    }}>
                      {evt.response_status}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{evt.latency_ms}ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
