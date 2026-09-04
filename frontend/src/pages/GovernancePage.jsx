import React, { useState } from 'react';
import PageHeader from '../components/layout/PageHeader';
import SecurityGovernanceCard from '../components/SecurityGovernanceCard';
import ControlAssuranceCard from '../components/ControlAssuranceCard';
import GovernanceReviewCard from '../components/GovernanceReviewCard';
import { Scale, ShieldCheck, ClipboardCheck, History } from 'lucide-react';

export default function GovernancePage({ apiKey, permissions, onNavigate }) {
  const [activeTab, setActiveTab] = useState('posture'); // 'posture' | 'assurance' | 'reviews'

  return (
    <div className="governance-page">
      <PageHeader
        title="AI Security Governance & Control Assurance"
        subtitle="Policy governance, continuous control assurance testing, and periodic compliance audit reviews."
        helpText="Governance manages policy baselines, continuous control assurance, and compliance evidence. This operational surface is decoupled from live runtime gateway traffic."
        actions={
          <div className="tab-buttons-group">
            <button
              className={`tab-button ${activeTab === 'posture' ? 'tab-button-active' : ''}`}
              onClick={() => setActiveTab('posture')}
            >
              <Scale size={14} />
              <span>Risk Posture</span>
            </button>
            <button
              className={`tab-button ${activeTab === 'assurance' ? 'tab-button-active' : ''}`}
              onClick={() => setActiveTab('assurance')}
            >
              <ShieldCheck size={14} />
              <span>Control Assurance</span>
            </button>
            <button
              className={`tab-button ${activeTab === 'reviews' ? 'tab-button-active' : ''}`}
              onClick={() => setActiveTab('reviews')}
            >
              <ClipboardCheck size={14} />
              <span>Periodic Reviews</span>
            </button>
          </div>
        }
      />

      {activeTab === 'posture' && <SecurityGovernanceCard apiKey={apiKey} />}
      {activeTab === 'assurance' && <ControlAssuranceCard apiKey={apiKey} />}
      {activeTab === 'reviews' && <GovernanceReviewCard apiKey={apiKey} />}
    </div>
  );
}
