from enum import Enum
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class IncidentSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class IncidentPriority(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class IncidentType(str, Enum):
    SECURITY_REGRESSION = "SECURITY_REGRESSION"
    POSTURE_DEGRADATION = "POSTURE_DEGRADATION"
    MULTI_DOMAIN_VULNERABILITY = "MULTI_DOMAIN_VULNERABILITY"
    THREAT_SPIKE = "THREAT_SPIKE"
    MANUAL = "MANUAL"


class IncidentActionType(str, Enum):
    ACKNOWLEDGE_ALERT = "ACKNOWLEDGE_ALERT"
    ASSIGN_INCIDENT = "ASSIGN_INCIDENT"
    CHANGE_STATUS = "CHANGE_STATUS"
    MARK_FALSE_POSITIVE = "MARK_FALSE_POSITIVE"
    ATTACH_EVIDENCE = "ATTACH_EVIDENCE"
    ATTACH_REPORT = "ATTACH_REPORT"
    REQUEST_POLICY_REVIEW = "REQUEST_POLICY_REVIEW"


class SecurityIncidentNote(BaseModel):
    note_id: str
    incident_id: str
    author: str
    note: str
    created_at: datetime


class SecurityIncidentEvidence(BaseModel):
    evidence_id: str
    incident_id: str
    evidence_type: str
    source_id: Optional[str] = None
    description: str
    sha256_hash: str
    created_at: datetime
    created_by: str = "system"


class SecurityIncidentAction(BaseModel):
    action_id: str
    incident_id: str
    action_type: str
    requested_by: str
    approved_by: Optional[str] = None
    status: str = "COMPLETED"
    description: str
    created_at: datetime
    completed_at: Optional[datetime] = None


class IncidentTimelineEvent(BaseModel):
    timestamp: datetime
    event_type: str
    source: str
    source_id: Optional[str] = None
    severity: Optional[str] = None
    description: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SecurityIncident(BaseModel):
    incident_id: str
    title: str
    description: str
    incident_type: str = IncidentType.SECURITY_REGRESSION.value
    severity: str = IncidentSeverity.MEDIUM.value
    status: str = IncidentStatus.OPEN.value
    priority: str = IncidentPriority.P2.value
    created_at: datetime
    updated_at: datetime
    detected_at: datetime
    resolved_at: Optional[datetime] = None
    created_by: str = "system"
    assigned_to: Optional[str] = None
    source_alert_id: Optional[str] = None
    campaign_id: Optional[str] = None
    campaign_run_id: Optional[str] = None
    policy_version: Optional[str] = "1.0.0"
    risk_score: int = Field(default=0, ge=0, le=100)


class IncidentSummary(BaseModel):
    total_incidents: int = 0
    open_incidents: int = 0
    investigating_incidents: int = 0
    contained_incidents: int = 0
    resolved_incidents: int = 0
    false_positives: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    avg_risk_score: float = 0.0


class IncidentCreateRequest(BaseModel):
    title: str
    description: str
    incident_type: Optional[str] = IncidentType.SECURITY_REGRESSION.value
    severity: Optional[str] = IncidentSeverity.MEDIUM.value
    priority: Optional[str] = IncidentPriority.P2.value
    source_alert_id: Optional[str] = None
    campaign_id: Optional[str] = None
    campaign_run_id: Optional[str] = None
    policy_version: Optional[str] = "1.0.0"


class IncidentUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[str] = None


class IncidentAssignRequest(BaseModel):
    assigned_to: str


class IncidentStatusRequest(BaseModel):
    status: str
    reason: Optional[str] = None


class IncidentNoteRequest(BaseModel):
    note: str


class IncidentEvidenceRequest(BaseModel):
    evidence_type: str = "MANUAL"
    source_id: Optional[str] = None
    description: str
    raw_content: Optional[str] = None


class IncidentActionRequest(BaseModel):
    action_type: str
    description: str
    approved_by: Optional[str] = None


class IncidentDetailResponse(BaseModel):
    incident: SecurityIncident
    events: List[IncidentTimelineEvent] = Field(default_factory=list)
    evidence: List[SecurityIncidentEvidence] = Field(default_factory=list)
    notes: List[SecurityIncidentNote] = Field(default_factory=list)
    actions: List[SecurityIncidentAction] = Field(default_factory=list)
    timeline: List[IncidentTimelineEvent] = Field(default_factory=list)
    related_alerts: List[Dict[str, Any]] = Field(default_factory=list)
    related_campaign_run: Optional[Dict[str, Any]] = None
    findings: List[Dict[str, Any]] = Field(default_factory=list)
