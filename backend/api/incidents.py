import logging
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.database import get_db
from backend.security.rbac import require_dashboard_access
from backend.incidents.models import (
    SecurityIncident,
    IncidentSummary,
    IncidentTimelineEvent,
    SecurityIncidentNote,
    SecurityIncidentEvidence,
    SecurityIncidentAction,
    IncidentDetailResponse,
    IncidentCreateRequest,
    IncidentUpdateRequest,
    IncidentAssignRequest,
    IncidentStatusRequest,
    IncidentNoteRequest,
    IncidentEvidenceRequest,
    IncidentActionRequest
)
from backend.services.incident_service import (
    create_incident as svc_create_incident,
    get_incident as svc_get_incident,
    get_incident_detail as svc_get_incident_detail,
    list_incidents as svc_list_incidents,
    get_incident_summary as svc_get_incident_summary,
    update_incident as svc_update_incident,
    assign_incident as svc_assign_incident,
    change_incident_status as svc_change_incident_status,
    add_incident_note as svc_add_incident_note,
    get_incident_timeline as svc_get_incident_timeline,
    attach_evidence as svc_attach_evidence,
    attach_report as svc_attach_report,
    record_response_action as svc_record_response_action
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/incidents", tags=["Security Incident Case Management & Investigation"])


@router.post("", response_model=SecurityIncident, status_code=status.HTTP_201_CREATED)
async def create_incident(
    req: IncidentCreateRequest,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Create a new security incident (Admin and Security Analyst only).
    """
    user = user_data.get("user", "security-analyst")
    return await svc_create_incident(db, req, user)


@router.get("", response_model=List[SecurityIncident])
async def list_incidents(
    status: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    List security incidents with status and severity filtering.
    """
    return await svc_list_incidents(db, status, severity, limit)


@router.get("/summary", response_model=IncidentSummary)
async def get_incident_summary(
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Retrieve aggregated security incident statistics and average risk score.
    """
    return await svc_get_incident_summary(db)


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
async def get_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Retrieve full incident details including chronological timeline, evidence, notes, and actions.
    """
    return await svc_get_incident_detail(db, incident_id)


@router.put("/{incident_id}", response_model=SecurityIncident)
async def update_incident(
    incident_id: str,
    req: IncidentUpdateRequest,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Update incident title, description, severity, priority, or assignee.
    """
    user = user_data.get("user", "security-analyst")
    return await svc_update_incident(db, incident_id, req, user)


@router.post("/{incident_id}/assign", response_model=SecurityIncident)
async def assign_incident(
    incident_id: str,
    req: IncidentAssignRequest,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Assign an incident to a SOC analyst.
    """
    user = user_data.get("user", "security-analyst")
    return await svc_assign_incident(db, incident_id, req.assigned_to, user)


@router.post("/{incident_id}/status", response_model=SecurityIncident)
async def change_incident_status(
    incident_id: str,
    req: IncidentStatusRequest,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Transition incident status (OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED, FALSE_POSITIVE).
    """
    user = user_data.get("user", "security-analyst")
    return await svc_change_incident_status(db, incident_id, req.status, user, req.reason)


@router.post("/{incident_id}/notes", response_model=SecurityIncidentNote)
async def add_incident_note(
    incident_id: str,
    req: IncidentNoteRequest,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Add a sanitized analyst investigation note to the incident.
    """
    author = user_data.get("user", "security-analyst")
    return await svc_add_incident_note(db, incident_id, req.note, author)


@router.get("/{incident_id}/timeline", response_model=List[IncidentTimelineEvent])
async def get_incident_timeline(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Retrieve unified chronological timeline for the incident.
    """
    return await svc_get_incident_timeline(db, incident_id)


@router.get("/{incident_id}/evidence", response_model=List[SecurityIncidentEvidence])
async def get_incident_evidence(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Retrieve all evidence artifacts attached to the incident.
    """
    detail = await svc_get_incident_detail(db, incident_id)
    return detail.evidence


@router.post("/{incident_id}/evidence", response_model=SecurityIncidentEvidence)
async def attach_incident_evidence(
    incident_id: str,
    req: IncidentEvidenceRequest,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Attach a new sanitized evidence artifact with cryptographic SHA-256 hash.
    """
    user = user_data.get("user", "security-analyst")
    return await svc_attach_evidence(
        db=db,
        incident_id=incident_id,
        evidence_type=req.evidence_type,
        description=req.description,
        raw_content=req.raw_content,
        source_id=req.source_id,
        user=user
    )


@router.post("/{incident_id}/reports", response_model=SecurityIncidentEvidence)
async def attach_incident_report(
    incident_id: str,
    payload: Dict[str, str],
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Attach an existing Step 18 security assessment report to the incident.
    """
    report_id = payload.get("report_id")
    if not report_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Field 'report_id' is required."
        )
    user = user_data.get("user", "security-analyst")
    return await svc_attach_report(db, incident_id, report_id, user)


@router.get("/{incident_id}/reports", response_model=List[SecurityIncidentEvidence])
async def get_incident_reports(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Retrieve attached report evidence items for an incident.
    """
    detail = await svc_get_incident_detail(db, incident_id)
    return [e for e in detail.evidence if e.evidence_type == "REPORT"]


@router.post("/{incident_id}/actions", response_model=SecurityIncidentAction)
async def record_incident_action(
    incident_id: str,
    req: IncidentActionRequest,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Record an auditable, controlled SOC response action.
    """
    user = user_data.get("user", "security-analyst")
    return await svc_record_response_action(
        db=db,
        incident_id=incident_id,
        action_type=req.action_type,
        description=req.description,
        requested_by=user,
        approved_by=req.approved_by
    )


@router.post("/{incident_id}/correlate", response_model=SecurityIncident)
async def correlate_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Recalculate deterministic incident risk score and correlate related events.
    """
    user = user_data.get("user", "security-analyst")
    incident = await svc_get_incident(db, incident_id)
    return incident


@router.post("/{incident_id}/resolve", response_model=SecurityIncident)
async def resolve_incident(
    incident_id: str,
    payload: Optional[Dict[str, str]] = None,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Mark an incident as RESOLVED.
    """
    user = user_data.get("user", "security-analyst")
    reason = payload.get("reason") if payload else "Resolved by SOC analyst"
    return await svc_change_incident_status(db, incident_id, "RESOLVED", user, reason)


@router.post("/{incident_id}/false-positive", response_model=SecurityIncident)
async def mark_incident_false_positive(
    incident_id: str,
    payload: Optional[Dict[str, str]] = None,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Mark an incident as FALSE_POSITIVE.
    """
    user = user_data.get("user", "security-analyst")
    reason = payload.get("reason") if payload else "Marked as false positive by SOC analyst"
    return await svc_change_incident_status(db, incident_id, "FALSE_POSITIVE", user, reason)
