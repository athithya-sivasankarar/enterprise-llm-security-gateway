import React, { useState } from 'react';
import PageHeader from '../components/layout/PageHeader';
import SecurityAttackSurfaceCard from '../components/SecurityAttackSurfaceCard';
import SecurityExposureCard from '../components/SecurityExposureCard';
import { Boxes, ShieldCheck, Layers } from 'lucide-react';

export default function AssetsPage({ apiKey, permissions, onNavigate }) {
  const [activeTab, setActiveTab] = useState('inventory'); // 'inventory' | 'exposures'

  return (
    <div className="assets-page">
      <PageHeader
        title="AI Asset Inventory & Attack Surface"
        subtitle="Catalog and attack surface mapping of all protected AI components, LLM models, gateway APIs, and semantic cache tiers."
        helpText="Assets are the AI components being protected and tested. Track asset criticality, control coverage mappings, and active security exposures across your AI infrastructure."
        actions={
          <div className="tab-buttons-group">
            <button
              className={`tab-button ${activeTab === 'inventory' ? 'tab-button-active' : ''}`}
              onClick={() => setActiveTab('inventory')}
            >
              <Boxes size={14} />
              <span>Asset Inventory</span>
            </button>
            <button
              className={`tab-button ${activeTab === 'exposures' ? 'tab-button-active' : ''}`}
              onClick={() => setActiveTab('exposures')}
            >
              <ShieldCheck size={14} />
              <span>Active Exposures</span>
            </button>
          </div>
        }
      />

      {activeTab === 'inventory' ? (
        <SecurityAttackSurfaceCard apiKey={apiKey} />
      ) : (
        <SecurityExposureCard apiKey={apiKey} />
      )}
    </div>
  );
}
