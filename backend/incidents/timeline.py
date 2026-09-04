import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, and_

from backend.db.models import (
    SecurityIncidentModel,
    SecurityIncidentEventModel,
    SecurityIncidentEvidenceModel,
    SecurityIncidentNoteModel,
    SecurityIncidentActionModel,
    SecurityAlertModel,
    SecurityRegressionModel,
    SecurityCampaignRunModel,
    SecurityReportModel
)
from backend.incidents.models import IncidentTimelineEvent
from backend.incidents.sanitizer import sanitize_incident_metadata, sanitize_incident_text

logger = logging.getLogger(__name__)


async def build_incident_timeline(
    db: AsyncSession,
    incident: SecurityIncidentModel
) -> List[IncidentTimelineEvent]:
    """
    Deterministically build a unified, chronological timeline for a security incident.
    Aggregates incident lifecycle events, linked alerts, campaign executions, regressions,
    evidence additions, analyst notes, and response actions.
    All events contain sanitized metadata only.
    """
    raw_events: List[IncidentTimelineEvent] = []

    # 1. Incident Creation Event
    raw_events.append(
        IncidentTimelineEvent(
            timestamp=incident.created_at,
            event_type="INCIDENT_CREATED",
            source="INCIDENT_ENGINE",
            source_id=incident.incident_id,
            severity=incident.severity,
            description=f"Security Incident '{incident.incident_id}' opened: {incident.title}",
            metadata={"status": incident.status, "priority": incident.priority, "risk_score": incident.risk_score}
        )
    )

    # 2. Persisted Incident Events
    stmt_ev = select(SecurityIncidentEventModel).where(
        SecurityIncidentEventModel.incident_id == incident.incident_id
    )
    res_ev = await db.execute(stmt_ev)
    for row in res_ev.scalars().all():
        raw_events.append(
            IncidentTimelineEvent(
                timestamp=row.event_timestamp,
                event_type=row.event_type,
                source=row.source_type,
                source_id=row.source_id,
                severity=row.severity,
                description=sanitize_incident_text(row.description),
                metadata=sanitize_incident_metadata(row.metadata_json or {})
            )
        )

    # 3. Linked Alert Event (if any)
    if incident.source_alert_id:
        stmt_alt = select(SecurityAlertModel).where(
            SecurityAlertModel.alert_id == incident.source_alert_id
        )
        res_alt = await db.execute(stmt_alt)
        alt_row = res_alt.scalar_one_or_none()
        if alt_row:
            raw_events.append(
                IncidentTimelineEvent(
                    timestamp=alt_row.created_at,
                    event_type="ALERT_TRIGGERED",
                    source="ALERT_ENGINE",
                    source_id=alt_row.alert_id,
                    severity=alt_row.severity,
                    description=f"Alert triggered: {sanitize_incident_text(alt_row.title)}",
                    metadata={"alert_type": alt_row.alert_type, "score_delta": alt_row.score_delta}
                )
            )

    # 4. Linked Campaign Run & Regressions (if any)
    if incident.campaign_run_id:
        stmt_crun = select(SecurityCampaignRunModel).where(
            SecurityCampaignRunModel.campaign_run_id == incident.campaign_run_id
        )
        res_crun = await db.execute(stmt_crun)
        crun_row = res_crun.scalar_one_or_none()
        if crun_row:
            raw_events.append(
                IncidentTimelineEvent(
                    timestamp=crun_row.started_at,
                    event_type="CAMPAIGN_EXECUTED",
                    source="CAMPAIGN_SERVICE",
                    source_id=crun_row.campaign_run_id,
                    severity="INFO",
                    description=f"Security assessment campaign run executed ({crun_row.total_tests} tests evaluated, Score: {crun_row.security_score}%)",
                    metadata={"score": crun_row.security_score, "score_delta": crun_row.score_delta}
                )
            )

        stmt_reg = select(SecurityRegressionModel).where(
            SecurityRegressionModel.campaign_run_id == incident.campaign_run_id
        )
        res_reg = await db.execute(stmt_reg)
        for r_row in res_reg.scalars().all():
            raw_events.append(
                IncidentTimelineEvent(
                    timestamp=r_row.created_at,
                    event_type="REGRESSION_DETECTED",
                    source="REGRESSION_ANALYZER",
                    source_id=r_row.regression_id,
                    severity=r_row.severity,
                    description=f"Security control regression detected in test '{r_row.test_id}' ({r_row.category}): {sanitize_incident_text(r_row.description)}",
                    metadata={"test_id": r_row.test_id, "category": r_row.category, "severity": r_row.severity}
                )
            )

    # 5. Attached Evidence
    stmt_evi = select(SecurityIncidentEvidenceModel).where(
        SecurityIncidentEvidenceModel.incident_id == incident.incident_id
    )
    res_evi = await db.execute(stmt_evi)
    for evi_row in res_evi.scalars().all():
        raw_events.append(
            IncidentTimelineEvent(
                timestamp=evi_row.created_at,
                event_type="EVIDENCE_ATTACHED",
                source="EVIDENCE_STORE",
                source_id=evi_row.evidence_id,
                severity="INFO",
                description=f"Evidence attached ({evi_row.evidence_type}): {sanitize_incident_text(evi_row.description)}",
                metadata={"sha256_hash": evi_row.sha256_hash, "created_by": evi_row.created_by}
            )
        )

    # 6. Analyst Notes
    stmt_notes = select(SecurityIncidentNoteModel).where(
        SecurityIncidentNoteModel.incident_id == incident.incident_id
    )
    res_notes = await db.execute(stmt_notes)
    for n_row in res_notes.scalars().all():
        raw_events.append(
            IncidentTimelineEvent(
                timestamp=n_row.created_at,
                event_type="ANALYST_NOTE_ADDED",
                source="SOC_ANALYST",
                source_id=n_row.note_id,
                severity="INFO",
                description=f"Analyst note from {n_row.author}: {sanitize_incident_text(n_row.note)}",
                metadata={"author": n_row.author}
            )
        )

    # 7. Response Actions
    stmt_act = select(SecurityIncidentActionModel).where(
        SecurityIncidentActionModel.incident_id == incident.incident_id
    )
    res_act = await db.execute(stmt_act)
    for a_row in res_act.scalars().all():
        raw_events.append(
            IncidentTimelineEvent(
                timestamp=a_row.created_at,
                event_type=f"ACTION_{a_row.action_type}",
                source="SOC_RESPONSE",
                source_id=a_row.action_id,
                severity="INFO",
                description=f"Controlled SOC Action '{a_row.action_type}' ({a_row.status}) by {a_row.requested_by}: {sanitize_incident_text(a_row.description)}",
                metadata={"action_type": a_row.action_type, "status": a_row.status, "requested_by": a_row.requested_by}
            )
        )

    # 8. Resolution Event (if resolved)
    if incident.resolved_at:
        raw_events.append(
            IncidentTimelineEvent(
                timestamp=incident.resolved_at,
                event_type="INCIDENT_RESOLVED" if incident.status == "RESOLVED" else f"INCIDENT_{incident.status}",
                source="INCIDENT_ENGINE",
                source_id=incident.incident_id,
                severity="INFO",
                description=f"Incident '{incident.incident_id}' transitioned to {incident.status}",
                metadata={"status": incident.status, "resolved_at": incident.resolved_at.isoformat()}
            )
        )

    # Deduplicate timeline items that have identical timestamp and event_type & source_id
    seen = set()
    unique_events: List[IncidentTimelineEvent] = []
    for ev in raw_events:
        key = (ev.timestamp.isoformat(), ev.event_type, ev.source_id or "")
        if key not in seen:
            seen.add(key)
            unique_events.append(ev)

    # Sort strictly chronologically
    unique_events.sort(key=lambda x: x.timestamp)
    return unique_events
