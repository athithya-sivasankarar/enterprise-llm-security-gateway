import React from 'react';
import { ShieldCheck, ShieldAlert, FileText, Lock, AlertTriangle, Zap, EyeOff, Ban } from 'lucide-react';

export default function KpiCards({ summary }) {
  if (!summary) return null;

  const cards = [
    {
      title: 'Total Requests',
      value: summary.total_requests.toLocaleString(),
      icon: FileText,
      className: 'kpi-blue',
      subtitle: 'Gateway throughput'
    },
    {
      title: 'Allowed',
      value: summary.allowed.toLocaleString(),
      icon: ShieldCheck,
      className: 'kpi-allow',
      subtitle: 'Passed safety checks'
    },
    {
      title: 'Blocked (Input)',
      value: summary.blocked.toLocaleString(),
      icon: ShieldAlert,
      className: 'kpi-block',
      subtitle: 'Injections & policy blocks'
    },
    {
      title: 'Sanitized',
      value: summary.sanitized.toLocaleString(),
      icon: EyeOff,
      className: 'kpi-sanitize',
      subtitle: 'PII Redacted'
    },
    {
      title: 'PII Detections',
      value: summary.pii_detections.toLocaleString(),
      icon: Lock,
      className: 'kpi-sanitize',
      subtitle: 'Presidio detections'
    },
    {
      title: 'Prompt Injections',
      value: summary.injection_detections.toLocaleString(),
      icon: AlertTriangle,
      className: 'kpi-block',
      subtitle: 'Threat attacks stopped'
    },
    {
      title: 'Response Blocks',
      value: summary.response_blocks.toLocaleString(),
      icon: Ban,
      className: 'kpi-block',
      subtitle: 'Secrets / Unsafe outputs'
    },
    {
      title: 'Avg Latency',
      value: `${summary.average_latency_ms}ms`,
      icon: Zap,
      className: 'kpi-blue',
      subtitle: 'End-to-end processing'
    }
  ];

  return (
    <div className="kpi-grid">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div key={idx} className={`kpi-card ${card.className}`}>
            <div className="kpi-header">
              <span className="kpi-title">{card.title}</span>
              <Icon className="kpi-icon" />
            </div>
            <div className="kpi-value">{card.value}</div>
            <div className="kpi-footer">{card.subtitle}</div>
          </div>
        );
      })}
    </div>
  );
}
