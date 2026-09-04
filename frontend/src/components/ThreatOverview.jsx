import React from 'react';
import { AlertOctagon } from 'lucide-react';

export default function ThreatOverview({ threats }) {
  const threatList = threats || [];
  const maxCount = threatList.reduce((max, t) => Math.max(max, t.count), 1);

  return (
    <div className="dashboard-panel">
      <div className="panel-header">
        <h2 className="panel-title">
          <AlertOctagon size={18} style={{ color: 'var(--status-block)' }} />
          Threat Distribution
        </h2>
        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          {threatList.reduce((acc, t) => acc + t.count, 0)} Total Threats
        </span>
      </div>

      {threatList.length === 0 ? (
        <div className="empty-state">No security threats detected.</div>
      ) : (
        <div className="threat-list">
          {threatList.map((item, idx) => {
            const percentage = Math.round((item.count / maxCount) * 100);
            return (
              <div key={idx} className="threat-item">
                <div className="threat-meta">
                  <span className="threat-name">{item.type}</span>
                  <span className="threat-count">{item.count} events</span>
                </div>
                <div className="threat-bar-bg">
                  <div
                    className="threat-bar-fill"
                    style={{ width: `${Math.max(percentage, 5)}%` }}
                  ></div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
