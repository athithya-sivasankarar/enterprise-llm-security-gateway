import React from 'react';
import { HelpCircle } from 'lucide-react';

export default function PageHeader({
  title,
  subtitle,
  helpText,
  actions,
  badge
}) {
  return (
    <div className="page-header-container">
      <div className="page-header-left">
        <div className="page-title-row">
          <h1 className="page-title">{title}</h1>
          {badge && <span className="page-header-badge">{badge}</span>}
        </div>
        {subtitle && <p className="page-subtitle">{subtitle}</p>}
        {helpText && (
          <div className="page-help-box">
            <HelpCircle size={14} className="help-icon" />
            <span>{helpText}</span>
          </div>
        )}
      </div>
      {actions && <div className="page-header-actions">{actions}</div>}
    </div>
  );
}
