import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import SecuritySchedulerCard from '../components/SecuritySchedulerCard';
import { Clock } from 'lucide-react';

export default function SchedulerPage({ apiKey, permissions, onNavigate }) {
  return (
    <div className="scheduler-page">
      <PageHeader
        title="Automated Campaign Scheduler"
        subtitle="Configure automated cron-like recurring execution schedules for security campaigns to continuously evaluate gateway defenses."
        helpText="The scheduler automatically runs security campaigns at defined intervals. Scheduled executions establish baselines and trigger SOC alerts on regression detection."
      />

      <SecuritySchedulerCard apiKey={apiKey} />
    </div>
  );
}
