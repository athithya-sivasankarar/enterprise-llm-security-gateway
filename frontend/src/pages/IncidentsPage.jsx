import React, { useState } from 'react';
import PageHeader from '../components/layout/PageHeader';
import SecurityIncidentsCard from '../components/SecurityIncidentsCard';
import IncidentInvestigationCard from '../components/IncidentInvestigationCard';
import { AlertTriangle, Plus, Shield, ArrowLeft } from 'lucide-react';

export default function IncidentsPage({ apiKey, permissions, onNavigate }) {
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);

  return (
    <div className="incidents-page">
      <PageHeader
        title="Security Incident Case Management & Investigation"
        subtitle="Formal case management, timeline reconstruction, evidence correlation, analyst notes, and containment workflows for AI security breaches."
        helpText="Incidents are security cases that require structured investigation and response. Correlate alert evidence, document root cause analysis, and record corrective remediation actions."
        actions={
          selectedIncidentId && (
            <button
              className="btn btn-outline d-flex align-items-center gap-1"
              onClick={() => setSelectedIncidentId(null)}
            >
              <ArrowLeft size={14} />
              <span>Back to Incident Case List</span>
            </button>
          )
        }
      />

      {/* Incident Case Management List */}
      <SecurityIncidentsCard
        apiKey={apiKey}
        userRole={permissions?.role}
        onSelectIncident={setSelectedIncidentId}
        selectedIncidentId={selectedIncidentId}
      />

      {/* Deep Incident Investigation Workspace Modal / Drawer */}
      {selectedIncidentId && (
        <div className="mt-6">
          <IncidentInvestigationCard
            apiKey={apiKey}
            userRole={permissions?.role}
            incidentId={selectedIncidentId}
            onClose={() => setSelectedIncidentId(null)}
          />
        </div>
      )}
    </div>
  );
}
