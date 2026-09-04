import uuid
import hashlib
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Tuple
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func, and_, or_

from backend.db.models import (
    SecurityIncidentModel,
    SecurityIncidentEventModel,
    SecurityIncidentEvidenceModel,
    SecurityIncidentNoteModel,
    SecurityIncidentActionModel,
    SecurityAlertModel,
    SecurityCampaignRunModel,
    SecurityRegressionModel,
    SecurityTestFindingModel,
    SecurityReportModel
)
from backend.incidents.models import (
    IncidentStatus,
    IncidentSeverity,
    IncidentPriority,
    IncidentActionType,
    SecurityIncident,
    IncidentSummary,
    IncidentTimelineEvent,
    SecurityIncidentNote,
    SecurityIncidentEvidence,
    SecurityIncidentAction,
    IncidentDetailResponse,
    IncidentCreateRequest,
    IncidentUpdateRequest
)
from backend.incidents.sanitizer import (
    sanitize_incident_text,
    sanitize_incident_note,
    sanitize_incident_metadata,
    sanitize_evidence_payload
)
from backend.incidents.scoring import calculate_incident_risk, classify_incident_severity
from backend.incidents.correlator import (
    find_correlatable_incident,
    generate_alert_correlation_fingerprint,
    evaluate_incident_correlation_factors
)
from backend.incidents.timeline import build_incident_timeline
from backend.observability.metrics import (
    record_incident_created_metric,
    set_incidents_open_metric,
    record_incident_resolved_metric,
    record_incident_action_metric,
    record_incident_correlation_metric,
    record_incident_correlation_error_metric,
    record_incident_risk_score_metric
)
from backend.observability.logging import log_security_event

logger = logging.getLogger(__name__)


def _to_security_incident(m: SecurityIncidentModel) -> SecurityIncident:
    return SecurityIncident(
        incident_id=m.incident_id,
        title=m.title,
        description=m.description,
        incident_type=m.incident_type,
        severity=m.severity,
        status=m.status,
        priority=m.priority,
        created_at=m.created_at,
        updated_at=m.updated_at,
        detected_at=m.detected_at,
        resolved_at=m.resolved_at,
        created_by=m.created_by,
        assigned_to=m.assigned_to,
        source_alert_id=m.source_alert_id,
        campaign_id=m.campaign_id,
        campaign_run_id=m.campaign_run_id,
        policy_version=m.policy_version or "1.0.0",
        risk_score=m.risk_score
    )


async def _sync_open_incident_gauges(db: AsyncSession) -> None:
    """
    Sync Prometheus gauges for open incident counts by severity.
    """
    try:
        stmt = (
            select(SecurityIncidentModel.severity, func.count(SecurityIncidentModel.id))
            .where(SecurityIncidentModel.status.in_([IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value]))
            .group_by(SecurityIncidentModel.severity)
        )
        res = await db.execute(stmt)
        counts = {sev: 0 for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
        for sev, cnt in res.all():
            if sev in counts:
                counts[sev] = cnt
        for sev, cnt in counts.items():
            set_incidents_open_metric(sev, cnt)
    except Exception as e:
        logger.debug(f"Failed to sync open incident gauges: {e}")


async def create_incident(
    db: AsyncSession,
    req: IncidentCreateRequest,
    user: str
) -> SecurityIncident:
    """
    Create a new security incident.
    """
    incident_id = f"inc-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)

    clean_title = sanitize_incident_text(req.title)
    clean_desc = sanitize_incident_text(req.description)

    # Evaluate risk score
    factors = await evaluate_incident_correlation_factors(
        db=db,
        campaign_id=req.campaign_id,
        campaign_run_id=req.campaign_run_id
    )

    risk_score = factors["risk_score"]
    severity = req.severity or factors["severity"]
    priority = req.priority or factors["priority"]

    model = SecurityIncidentModel(
        incident_id=incident_id,
        title=clean_title,
        description=clean_desc,
        incident_type=req.incident_type or "SECURITY_REGRESSION",
        severity=severity,
        status=IncidentStatus.OPEN.value,
        priority=priority,
        created_at=now,
        updated_at=now,
        detected_at=now,
        created_by=user,
        source_alert_id=req.source_alert_id,
        campaign_id=req.campaign_id,
        campaign_run_id=req.campaign_run_id,
        policy_version=req.policy_version or "1.0.0",
        risk_score=risk_score
    )

    db.add(model)

    # Initial event
    event = SecurityIncidentEventModel(
        event_id=f"ev-{uuid.uuid4().hex[:12]}",
        incident_id=incident_id,
        event_type="INCIDENT_CREATED",
        event_timestamp=now,
        source_type="MANUAL" if not req.source_alert_id else "ALERT",
        source_id=req.source_alert_id or incident_id,
        category="INCIDENT_LIFECYCLE",
        severity=severity,
        description=f"Incident '{incident_id}' opened by {user}",
        metadata_json={"risk_score": risk_score, "priority": priority},
        created_at=now
    )
    db.add(event)

    await db.commit()
    await db.refresh(model)

    # Metrics & SIEM
    record_incident_created_metric(model.incident_type, model.severity)
    record_incident_risk_score_metric(model.incident_type, float(model.risk_score))
    await _sync_open_incident_gauges(db)

    log_security_event(
        event_type="SECURITY_INCIDENT_CREATED",
        request_id=f"inc-create-{incident_id}",
        action="ALLOW",
        response_status=201,
        user=user,
        role="security-lead",
        threat_type=model.incident_type,
        risk_score=model.risk_score
    )

    return _to_security_incident(model)


async def get_incident(db: AsyncSession, incident_id: str) -> SecurityIncident:
    """
    Retrieve incident by incident_id.
    """
    stmt = select(SecurityIncidentModel).where(SecurityIncidentModel.incident_id == incident_id)
    res = await db.execute(stmt)
    model = res.scalar_one_or_none()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security incident '{incident_id}' not found."
        )
    return _to_security_incident(model)


async def list_incidents(
    db: AsyncSession,
    status_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    limit: int = 50
) -> List[SecurityIncident]:
    """
    List incidents with optional filtering.
    """
    query = select(SecurityIncidentModel).order_by(desc(SecurityIncidentModel.created_at))
    if status_filter:
        query = query.where(SecurityIncidentModel.status == status_filter.upper())
    if severity_filter:
        query = query.where(SecurityIncidentModel.severity == severity_filter.upper())

    query = query.limit(limit)
    res = await db.execute(query)
    rows = res.scalars().all()
    return [_to_security_incident(r) for r in rows]


async def get_incident_summary(db: AsyncSession) -> IncidentSummary:
    """
    Compute aggregated metrics across all security incidents.
    """
    stmt = select(SecurityIncidentModel)
    res = await db.execute(stmt)
    all_incidents = res.scalars().all()

    total = len(all_incidents)
    open_cnt = sum(1 for i in all_incidents if i.status == IncidentStatus.OPEN.value)
    investigating_cnt = sum(1 for i in all_incidents if i.status == IncidentStatus.INVESTIGATING.value)
    contained_cnt = sum(1 for i in all_incidents if i.status == IncidentStatus.CONTAINED.value)
    resolved_cnt = sum(1 for i in all_incidents if i.status == IncidentStatus.RESOLVED.value)
    false_positives = sum(1 for i in all_incidents if i.status == IncidentStatus.FALSE_POSITIVE.value)

    critical_cnt = sum(1 for i in all_incidents if i.severity == IncidentSeverity.CRITICAL.value and i.status in ("OPEN", "INVESTIGATING"))
    high_cnt = sum(1 for i in all_incidents if i.severity == IncidentSeverity.HIGH.value and i.status in ("OPEN", "INVESTIGATING"))
    medium_cnt = sum(1 for i in all_incidents if i.severity == IncidentSeverity.MEDIUM.value and i.status in ("OPEN", "INVESTIGATING"))
    low_cnt = sum(1 for i in all_incidents if i.severity == IncidentSeverity.LOW.value and i.status in ("OPEN", "INVESTIGATING"))

    active_scores = [i.risk_score for i in all_incidents if i.status in ("OPEN", "INVESTIGATING")]
    avg_score = round(sum(active_scores) / len(active_scores), 1) if active_scores else 0.0

    return IncidentSummary(
        total_incidents=total,
        open_incidents=open_cnt,
        investigating_incidents=investigating_cnt,
        contained_incidents=contained_cnt,
        resolved_incidents=resolved_cnt,
        false_positives=false_positives,
        critical_count=critical_cnt,
        high_count=high_cnt,
        medium_count=medium_cnt,
        low_count=low_cnt,
        avg_risk_score=avg_score
    )


async def update_incident(
    db: AsyncSession,
    incident_id: str,
    req: IncidentUpdateRequest,
    user: str
) -> SecurityIncident:
    """
    Update incident properties.
    """
    stmt = select(SecurityIncidentModel).where(SecurityIncidentModel.incident_id == incident_id)
    res = await db.execute(stmt)
    model = res.scalar_one_or_none()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security incident '{incident_id}' not found."
        )

    now = datetime.now(timezone.utc)
    if req.title:
        model.title = sanitize_incident_text(req.title)
    if req.description:
        model.description = sanitize_incident_text(req.description)
    if req.severity:
        model.severity = req.severity.upper()
    if req.priority:
        model.priority = req.priority.upper()
    if req.assigned_to is not None:
        model.assigned_to = sanitize_incident_text(req.assigned_to)

    model.updated_at = now
    await db.commit()
    await db.refresh(model)

    log_security_event(
        event_type="SECURITY_INCIDENT_UPDATED",
        request_id=f"inc-update-{incident_id}",
        action="ALLOW",
        response_status=200,
        user=user,
        role="security-lead",
        threat_type=model.incident_type
    )

    return _to_security_incident(model)


async def assign_incident(
    db: AsyncSession,
    incident_id: str,
    assigned_to: str,
    user: str
) -> SecurityIncident:
    """
    Assign an incident to a SOC analyst or team.
    """
    stmt = select(SecurityIncidentModel).where(SecurityIncidentModel.incident_id == incident_id)
    res = await db.execute(stmt)
    model = res.scalar_one_or_none()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security incident '{incident_id}' not found."
        )

    clean_assignee = sanitize_incident_text(assigned_to)
    now = datetime.now(timezone.utc)
    model.assigned_to = clean_assignee
    if model.status == IncidentStatus.OPEN.value:
        model.status = IncidentStatus.INVESTIGATING.value
    model.updated_at = now

    event = SecurityIncidentEventModel(
        event_id=f"ev-{uuid.uuid4().hex[:12]}",
        incident_id=incident_id,
        event_type="INCIDENT_ASSIGNED",
        event_timestamp=now,
        source_type="SOC_ANALYST",
        source_id=user,
        category="INCIDENT_LIFECYCLE",
        severity="INFO",
        description=f"Incident assigned to {clean_assignee} by {user}",
        metadata_json={"assigned_to": clean_assignee, "assigned_by": user},
        created_at=now
    )
    db.add(event)

    # Record action
    action = SecurityIncidentActionModel(
        action_id=f"act-{uuid.uuid4().hex[:12]}",
        incident_id=incident_id,
        action_type=IncidentActionType.ASSIGN_INCIDENT.value,
        requested_by=user,
        approved_by=user,
        status="COMPLETED",
        description=f"Assigned incident to {clean_assignee}",
        created_at=now,
        completed_at=now
    )
    db.add(action)

    await db.commit()
    await db.refresh(model)

    record_incident_action_metric(IncidentActionType.ASSIGN_INCIDENT.value, "COMPLETED")
    await _sync_open_incident_gauges(db)

    log_security_event(
        event_type="SECURITY_INCIDENT_ASSIGNED",
        request_id=f"inc-assign-{incident_id}",
        action="ALLOW",
        response_status=200,
        user=user,
        role="security-lead",
        threat_type=model.incident_type
    )

    return _to_security_incident(model)


async def change_incident_status(
    db: AsyncSession,
    incident_id: str,
    new_status: str,
    user: str,
    reason: Optional[str] = None
) -> SecurityIncident:
    """
    Transition incident status (OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED, FALSE_POSITIVE).
    """
    stmt = select(SecurityIncidentModel).where(SecurityIncidentModel.incident_id == incident_id)
    res = await db.execute(stmt)
    model = res.scalar_one_or_none()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security incident '{incident_id}' not found."
        )

    norm_status = new_status.strip().upper()
    valid_statuses = [s.value for s in IncidentStatus]
    if norm_status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status '{new_status}'. Allowed statuses: {', '.join(valid_statuses)}"
        )

    now = datetime.now(timezone.utc)
    old_status = model.status
    model.status = norm_status
    model.updated_at = now

    if norm_status in (IncidentStatus.RESOLVED.value, IncidentStatus.CLOSED.value, IncidentStatus.FALSE_POSITIVE.value):
        model.resolved_at = now
    else:
        model.resolved_at = None

    clean_reason = sanitize_incident_text(reason or f"Status changed from {old_status} to {norm_status}")

    event = SecurityIncidentEventModel(
        event_id=f"ev-{uuid.uuid4().hex[:12]}",
        incident_id=incident_id,
        event_type="INCIDENT_STATUS_CHANGED",
        event_timestamp=now,
        source_type="SOC_ANALYST",
        source_id=user,
        category="INCIDENT_LIFECYCLE",
        severity="INFO",
        description=f"Status changed from {old_status} to {norm_status}. Reason: {clean_reason}",
        metadata_json={"old_status": old_status, "new_status": norm_status, "reason": clean_reason},
        created_at=now
    )
    db.add(event)

    action = SecurityIncidentActionModel(
        action_id=f"act-{uuid.uuid4().hex[:12]}",
        incident_id=incident_id,
        action_type=IncidentActionType.CHANGE_STATUS.value,
        requested_by=user,
        approved_by=user,
        status="COMPLETED",
        description=f"Changed status to {norm_status}: {clean_reason}",
        created_at=now,
        completed_at=now
    )
    db.add(action)

    await db.commit()
    await db.refresh(model)

    if norm_status in (IncidentStatus.RESOLVED.value, IncidentStatus.CLOSED.value):
        record_incident_resolved_metric(norm_status)
    elif norm_status == IncidentStatus.FALSE_POSITIVE.value:
        record_incident_resolved_metric("FALSE_POSITIVE")

    record_incident_action_metric(IncidentActionType.CHANGE_STATUS.value, "COMPLETED")
    await _sync_open_incident_gauges(db)

    siem_type = (
        "SECURITY_INCIDENT_RESOLVED" if norm_status == IncidentStatus.RESOLVED.value
        else "SECURITY_INCIDENT_FALSE_POSITIVE" if norm_status == IncidentStatus.FALSE_POSITIVE.value
        else "SECURITY_INCIDENT_STATUS_CHANGED"
    )

    log_security_event(
        event_type=siem_type,
        request_id=f"inc-status-{incident_id}",
        action="ALLOW",
        response_status=200,
        user=user,
        role="security-lead",
        threat_type=model.incident_type
    )

    return _to_security_incident(model)


async def add_incident_note(
    db: AsyncSession,
    incident_id: str,
    note_text: str,
    author: str
) -> SecurityIncidentNote:
    """
    Add a sanitized analyst note to an incident.
    """
    stmt = select(SecurityIncidentModel).where(SecurityIncidentModel.incident_id == incident_id)
    res = await db.execute(stmt)
    model = res.scalar_one_or_none()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security incident '{incident_id}' not found."
        )

    clean_note = sanitize_incident_note(note_text)
    if not clean_note.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Note content cannot be empty."
        )

    now = datetime.now(timezone.utc)
    note_id = f"note-{uuid.uuid4().hex[:12]}"
    note_row = SecurityIncidentNoteModel(
        note_id=note_id,
        incident_id=incident_id,
        author=author,
        note=clean_note,
        created_at=now
    )
    db.add(note_row)

    model.updated_at = now
    await db.commit()
    await db.refresh(note_row)

    log_security_event(
        event_type="SECURITY_INCIDENT_UPDATED",
        request_id=f"inc-note-{note_id}",
        action="ALLOW",
        response_status=200,
        user=author,
        role="security-analyst",
        threat_type="ANALYST_NOTE"
    )

    return SecurityIncidentNote(
        note_id=note_row.note_id,
        incident_id=note_row.incident_id,
        author=note_row.author,
        note=note_row.note,
        created_at=note_row.created_at
    )


async def get_incident_timeline(
    db: AsyncSession,
    incident_id: str
) -> List[IncidentTimelineEvent]:
    """
    Retrieve deterministic chronological timeline for an incident.
    """
    stmt = select(SecurityIncidentModel).where(SecurityIncidentModel.incident_id == incident_id)
    res = await db.execute(stmt)
    model = res.scalar_one_or_none()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security incident '{incident_id}' not found."
        )

    return await build_incident_timeline(db, model)


async def attach_evidence(
    db: AsyncSession,
    incident_id: str,
    evidence_type: str,
    description: str,
    raw_content: Optional[str] = None,
    source_id: Optional[str] = None,
    user: str = "system"
) -> SecurityIncidentEvidence:
    """
    Attach sanitized, cryptographically hashed evidence artifact to incident.
    """
    stmt = select(SecurityIncidentModel).where(SecurityIncidentModel.incident_id == incident_id)
    res = await db.execute(stmt)
    model = res.scalar_one_or_none()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security incident '{incident_id}' not found."
        )

    clean_desc = sanitize_evidence_payload(description, raw_content)
    now = datetime.now(timezone.utc)
    evidence_id = f"evd-{uuid.uuid4().hex[:12]}"

    # Deterministic SHA-256 hash
    hash_payload = f"{incident_id}|{evidence_type}|{clean_desc}|{now.isoformat()}"
    sha256_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()

    evi_row = SecurityIncidentEvidenceModel(
        evidence_id=evidence_id,
        incident_id=incident_id,
        evidence_type=evidence_type.upper(),
        source_id=source_id,
        description=clean_desc,
        sha256_hash=sha256_hash,
        created_at=now,
        created_by=user
    )
    db.add(evi_row)

    model.updated_at = now
    await db.commit()
    await db.refresh(evi_row)

    log_security_event(
        event_type="SECURITY_INCIDENT_EVIDENCE_ATTACHED",
        request_id=f"inc-evd-{evidence_id}",
        action="ALLOW",
        response_status=200,
        user=user,
        role="security-analyst",
        threat_type=evidence_type
    )

    return SecurityIncidentEvidence(
        evidence_id=evi_row.evidence_id,
        incident_id=evi_row.incident_id,
        evidence_type=evi_row.evidence_type,
        source_id=evi_row.source_id,
        description=evi_row.description,
        sha256_hash=evi_row.sha256_hash,
        created_at=evi_row.created_at,
        created_by=evi_row.created_by
    )


async def attach_report(
    db: AsyncSession,
    incident_id: str,
    report_id: str,
    user: str
) -> SecurityIncidentEvidence:
    """
    Attach an existing Step 18 security assessment report as auditable evidence.
    """
    stmt_rep = select(SecurityReportModel).where(SecurityReportModel.report_id == report_id)
    res_rep = await db.execute(stmt_rep)
    report = res_rep.scalar_one_or_none()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security report '{report_id}' not found."
        )

    desc_text = f"Security Assessment Report: {report.title} (Type: {report.report_type}, Score: {report.security_score}%, Hash: {report.report_hash})"
    return await attach_evidence(
        db=db,
        incident_id=incident_id,
        evidence_type="REPORT",
        description=desc_text,
        source_id=report_id,
        user=user
    )


async def record_response_action(
    db: AsyncSession,
    incident_id: str,
    action_type: str,
    description: str,
    requested_by: str,
    approved_by: Optional[str] = None,
    status: str = "COMPLETED"
) -> SecurityIncidentAction:
    """
    Record an auditable, controlled SOC response action.
    """
    stmt = select(SecurityIncidentModel).where(SecurityIncidentModel.incident_id == incident_id)
    res = await db.execute(stmt)
    model = res.scalar_one_or_none()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security incident '{incident_id}' not found."
        )

    clean_desc = sanitize_incident_text(description)
    now = datetime.now(timezone.utc)
    action_id = f"act-{uuid.uuid4().hex[:12]}"

    action_row = SecurityIncidentActionModel(
        action_id=action_id,
        incident_id=incident_id,
        action_type=action_type.upper(),
        requested_by=requested_by,
        approved_by=approved_by or requested_by,
        status=status.upper(),
        description=clean_desc,
        created_at=now,
        completed_at=now
    )
    db.add(action_row)

    model.updated_at = now
    await db.commit()
    await db.refresh(action_row)

    record_incident_action_metric(action_type, status)

    log_security_event(
        event_type="SECURITY_INCIDENT_ACTION_REQUESTED",
        request_id=f"inc-act-{action_id}",
        action="ALLOW",
        response_status=200,
        user=requested_by,
        role="security-lead",
        threat_type=action_type
    )

    return SecurityIncidentAction(
        action_id=action_row.action_id,
        incident_id=action_row.incident_id,
        action_type=action_row.action_type,
        requested_by=action_row.requested_by,
        approved_by=action_row.approved_by,
        status=action_row.status,
        description=action_row.description,
        created_at=action_row.created_at,
        completed_at=action_row.completed_at
    )


async def correlate_alert_safe(
    db: AsyncSession,
    alert: SecurityAlertModel,
    campaign_id: Optional[str] = None,
    campaign_run_id: Optional[str] = None,
    policy_version: Optional[str] = "1.0.0"
) -> Optional[SecurityIncident]:
    """
    CRITICAL RELIABILITY REQUIREMENT:
    Correlate an alert into an existing or new Security Incident in a fail-safe, non-blocking manner.
    Failures in incident correlation or persistence will NEVER raise or fail the caller.
    """
    try:
        now = datetime.now(timezone.utc)
        # Check for existing open incident to correlate
        existing_incident = await find_correlatable_incident(
            db=db,
            campaign_id=campaign_id or alert.campaign_id,
            campaign_run_id=campaign_run_id or alert.campaign_run_id,
            source_alert_id=alert.alert_id,
            created_at=now
        )

        factors = await evaluate_incident_correlation_factors(
            db=db,
            campaign_id=campaign_id or alert.campaign_id,
            campaign_run_id=campaign_run_id or alert.campaign_run_id,
            alert=alert
        )

        if existing_incident:
            # Append correlation event to existing incident and update risk score
            existing_incident.risk_score = max(existing_incident.risk_score, factors["risk_score"])
            existing_incident.severity = classify_incident_severity(existing_incident.risk_score)
            existing_incident.updated_at = now

            event = SecurityIncidentEventModel(
                event_id=f"ev-{uuid.uuid4().hex[:12]}",
                incident_id=existing_incident.incident_id,
                event_type="ALERT_CORRELATED",
                event_timestamp=now,
                source_type="ALERT",
                source_id=alert.alert_id,
                category="CORRELATION",
                severity=alert.severity,
                description=f"Correlated related alert: {sanitize_incident_text(alert.title)}",
                metadata_json={"alert_id": alert.alert_id, "score_delta": alert.score_delta},
                created_at=now
            )
            db.add(event)
            await db.commit()
            await db.refresh(existing_incident)

            record_incident_correlation_metric("CORRELATED_EXISTING")
            return _to_security_incident(existing_incident)
        else:
            # Create new correlated incident
            incident_id = f"inc-{uuid.uuid4().hex[:12]}"
            title = f"Security Incident: {sanitize_incident_text(alert.title)}"
            desc = f"Correlated security incident triggered by alert '{alert.alert_id}'. {sanitize_incident_text(alert.description)}"

            new_incident = SecurityIncidentModel(
                incident_id=incident_id,
                title=title,
                description=desc,
                incident_type=alert.alert_type or "SECURITY_REGRESSION",
                severity=factors["severity"],
                status=IncidentStatus.OPEN.value,
                priority=factors["priority"],
                created_at=now,
                updated_at=now,
                detected_at=now,
                created_by="system:alert-correlator",
                source_alert_id=alert.alert_id,
                campaign_id=campaign_id or alert.campaign_id,
                campaign_run_id=campaign_run_id or alert.campaign_run_id,
                policy_version=policy_version or alert.policy_version or "1.0.0",
                risk_score=factors["risk_score"]
            )
            db.add(new_incident)

            event = SecurityIncidentEventModel(
                event_id=f"ev-{uuid.uuid4().hex[:12]}",
                incident_id=incident_id,
                event_type="INCIDENT_CREATED_FROM_ALERT",
                event_timestamp=now,
                source_type="ALERT",
                source_id=alert.alert_id,
                category="CORRELATION",
                severity=factors["severity"],
                description=f"Incident opened automatically from alert '{alert.alert_id}'",
                metadata_json={"alert_type": alert.alert_type, "risk_score": factors["risk_score"]},
                created_at=now
            )
            db.add(event)
            await db.commit()
            await db.refresh(new_incident)

            record_incident_created_metric(new_incident.incident_type, new_incident.severity)
            record_incident_risk_score_metric(new_incident.incident_type, float(new_incident.risk_score))
            record_incident_correlation_metric("CREATED_NEW")
            await _sync_open_incident_gauges(db)

            log_security_event(
                event_type="SECURITY_INCIDENT_CREATED",
                request_id=f"inc-auto-{incident_id}",
                action="ALLOW",
                response_status=201,
                user="system:alert-correlator",
                role="system",
                threat_type=new_incident.incident_type,
                risk_score=new_incident.risk_score
            )

            return _to_security_incident(new_incident)

    except Exception as e:
        logger.error(f"Fail-safe incident correlation caught error (non-blocking): {e}", exc_info=True)
        record_incident_correlation_error_metric(type(e).__name__)
        log_security_event(
            event_type="SECURITY_INCIDENT_CORRELATION_ERROR",
            request_id=f"inc-err-{alert.alert_id}",
            action="ERROR",
            response_status=500,
            user="system:alert-correlator",
            role="system",
            threat_type="CORRELATION_FAILURE"
        )
        return None


async def get_incident_detail(
    db: AsyncSession,
    incident_id: str
) -> IncidentDetailResponse:
    """
    Retrieve comprehensive incident details for deep SOC investigation view.
    """
    stmt = select(SecurityIncidentModel).where(SecurityIncidentModel.incident_id == incident_id)
    res = await db.execute(stmt)
    model = res.scalar_one_or_none()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security incident '{incident_id}' not found."
        )

    # 1. Timeline
    timeline = await build_incident_timeline(db, model)

    # 2. Evidence
    stmt_evi = select(SecurityIncidentEvidenceModel).where(SecurityIncidentEvidenceModel.incident_id == incident_id)
    res_evi = await db.execute(stmt_evi)
    evidence = [
        SecurityIncidentEvidence(
            evidence_id=r.evidence_id,
            incident_id=r.incident_id,
            evidence_type=r.evidence_type,
            source_id=r.source_id,
            description=r.description,
            sha256_hash=r.sha256_hash,
            created_at=r.created_at,
            created_by=r.created_by
        ) for r in res_evi.scalars().all()
    ]

    # 3. Notes
    stmt_notes = select(SecurityIncidentNoteModel).where(SecurityIncidentNoteModel.incident_id == incident_id)
    res_notes = await db.execute(stmt_notes)
    notes = [
        SecurityIncidentNote(
            note_id=r.note_id,
            incident_id=r.incident_id,
            author=r.author,
            note=r.note,
            created_at=r.created_at
        ) for r in res_notes.scalars().all()
    ]

    # 4. Actions
    stmt_act = select(SecurityIncidentActionModel).where(SecurityIncidentActionModel.incident_id == incident_id)
    res_act = await db.execute(stmt_act)
    actions = [
        SecurityIncidentAction(
            action_id=r.action_id,
            incident_id=r.incident_id,
            action_type=r.action_type,
            requested_by=r.requested_by,
            approved_by=r.approved_by,
            status=r.status,
            description=r.description,
            created_at=r.created_at,
            completed_at=r.completed_at
        ) for r in res_act.scalars().all()
    ]

    # 5. Related alerts
    related_alerts = []
    if model.campaign_id:
        stmt_alt = select(SecurityAlertModel).where(SecurityAlertModel.campaign_id == model.campaign_id).limit(10)
        res_alt = await db.execute(stmt_alt)
        for a in res_alt.scalars().all():
            related_alerts.append({
                "alert_id": a.alert_id,
                "title": a.title,
                "alert_type": a.alert_type,
                "severity": a.severity,
                "status": a.status,
                "created_at": a.created_at.isoformat()
            })

    # 6. Related campaign run
    related_run = None
    if model.campaign_run_id:
        stmt_run = select(SecurityCampaignRunModel).where(SecurityCampaignRunModel.campaign_run_id == model.campaign_run_id)
        res_run = await db.execute(stmt_run)
        crun = res_run.scalar_one_or_none()
        if crun:
            related_run = {
                "campaign_run_id": crun.campaign_run_id,
                "campaign_id": crun.campaign_id,
                "status": crun.status,
                "security_score": crun.security_score,
                "baseline_score": crun.baseline_score,
                "score_delta": crun.score_delta,
                "regression_detected": crun.regression_detected
            }

    # 7. Findings & Regressions
    findings = []
    if model.campaign_run_id:
        stmt_reg = select(SecurityRegressionModel).where(SecurityRegressionModel.campaign_run_id == model.campaign_run_id)
        res_reg = await db.execute(stmt_reg)
        for r in res_reg.scalars().all():
            findings.append({
                "id": r.regression_id,
                "test_id": r.test_id,
                "category": r.category,
                "severity": r.severity,
                "description": r.description
            })

    return IncidentDetailResponse(
        incident=_to_security_incident(model),
        events=[],
        evidence=evidence,
        notes=notes,
        actions=actions,
        timeline=timeline,
        related_alerts=related_alerts,
        related_campaign_run=related_run,
        findings=findings
    )
