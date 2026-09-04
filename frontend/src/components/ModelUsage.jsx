import React from 'react';
import { Cpu } from 'lucide-react';

export default function ModelUsage({ models }) {
  const modelList = models || [];

  return (
    <div className="dashboard-panel">
      <div className="panel-header">
        <h2 className="panel-title">
          <Cpu size={18} style={{ color: 'var(--accent-cyan)' }} />
          Model Traffic & Latency
        </h2>
        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          {modelList.length} Upstream Models
        </span>
      </div>

      {modelList.length === 0 ? (
        <div className="empty-state">No model activity recorded yet.</div>
      ) : (
        <div className="events-table-wrapper">
          <table className="events-table">
            <thead>
              <tr>
                <th>Model</th>
                <th>Requests</th>
                <th>Allowed</th>
                <th>Blocked</th>
                <th>Avg Latency</th>
              </tr>
            </thead>
            <tbody>
              {modelList.map((m, idx) => (
                <tr key={idx}>
                  <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {m.model}
                  </td>
                  <td>{m.requests}</td>
                  <td>
                    <span className="badge badge-allow">{m.allowed}</span>
                  </td>
                  <td>
                    {m.blocked > 0 ? (
                      <span className="badge badge-block">{m.blocked}</span>
                    ) : (
                      '0'
                    )}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{m.average_latency_ms}ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
