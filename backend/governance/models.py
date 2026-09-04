from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field, field_validator


class RiskExceptionStatus(str, Enum):
    __test__ = False
    DRAFT = "DRAFT"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    CLOSED = "CLOSED"


class RiskExceptionSeverity(str, Enum):
    __test__ = False
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class GovernanceReviewStatus(str, Enum):
    __test__ = False
    PLANNED = "PLANNED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class GovernanceReviewType(str, Enum):
    __test__ = False
    CONTROL_EFFECTIVENESS = "CONTROL_EFFECTIVENESS"
    RISK_EXCEPTION_REVIEW = "RISK_EXCEPTION_REVIEW"
    EXPOSURE_REVIEW = "EXPOSURE_REVIEW"
    INCIDENT_REVIEW = "INCIDENT_REVIEW"
    EXECUTIVE_SECURITY_REVIEW = "EXECUTIVE_SECURITY_REVIEW"


class GovernanceDecision(str, Enum):
    __test__ = False
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    RENEW = "RENEW"
    REVOKE = "REVOKE"
    CLOSE = "CLOSE"


# =============================================================================
# Exception Requests & Responses
# =============================================================================

class RiskExceptionCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=255, description="Brief summary of the accepted risk exception")
    description: str = Field(..., min_length=5, description="Detailed explanation of the risk condition")
    risk_type: str = Field(default="GENERAL", description="Domain or type of risk (e.g., DLP, MODEL_ACCESS, PROMPT_INJECTION)")
    severity: RiskExceptionSeverity = Field(default=RiskExceptionSeverity.HIGH, description="Risk severity level")
    asset_id: Optional[str] = Field(default=None, description="Affected asset identifier")
    control_id: Optional[str] = Field(default=None, description="Affected security control identifier")
    exposure_id: Optional[str] = Field(default=None, description="Associated exposure identifier")
    incident_id: Optional[str] = Field(default=None, description="Associated incident identifier")
    source_type: Optional[str] = Field(default="MANUAL", description="Source finding type")
    source_id: Optional[str] = Field(default=None, description="Source finding identifier")
    business_justification: str = Field(..., min_length=10, description="Documented justification for why risk is accepted")
    compensating_controls: Optional[str] = Field(default=None, description="Documented compensating security controls")
    owner: str = Field(..., min_length=2, max_length=100, description="Risk owner responsible for remediation")
    expires_at: datetime = Field(..., description="Mandatory future expiration date for exception")
    review_due_at: Optional[datetime] = Field(default=None, description="Optional intermediate review due date")
    risk_score: Optional[int] = Field(default=None, ge=0, le=100, description="Optional custom risk score (0-100)")

    @field_validator("expires_at")
    @classmethod
    def validate_future_expiry(cls, v: datetime) -> datetime:
        now = datetime.now(timezone.utc)
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        if v <= now:
            raise ValueError("Exception expiration date (expires_at) must be strictly in the future")
        return v


class RiskExceptionUpdateRequest(BaseModel):
    title: Optional[str] = Field(default=None, min_length=3, max_length=255)
    description: Optional[str] = Field(default=None, min_length=5)
    risk_type: Optional[str] = None
    severity: Optional[RiskExceptionSeverity] = None
    business_justification: Optional[str] = Field(default=None, min_length=10)
    compensating_controls: Optional[str] = None
    owner: Optional[str] = Field(default=None, min_length=2, max_length=100)
    expires_at: Optional[datetime] = None
    review_due_at: Optional[datetime] = None

    @field_validator("expires_at")
    @classmethod
    def validate_future_expiry_if_present(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is not None:
            now = datetime.now(timezone.utc)
            if v.tzinfo is None:
                v = v.replace(tzinfo=timezone.utc)
            if v <= now:
                raise ValueError("Exception expiration date must be strictly in the future")
        return v


class RiskExceptionApprovalRequest(BaseModel):
    decision: GovernanceDecision = Field(..., description="APPROVE or REJECT")
    notes: Optional[str] = Field(default=None, description="Approver governance notes")
    approved_by: Optional[str] = Field(default=None, description="Approver username")


class RiskExceptionRenewalRequest(BaseModel):
    new_expires_at: datetime = Field(..., description="Mandatory new future expiration date")
    renewal_justification: str = Field(..., min_length=10, description="Business justification for renewal")
    reviewer: Optional[str] = Field(default=None, description="Reviewer renewing the exception")

    @field_validator("new_expires_at")
    @classmethod
    def validate_renewal_future(cls, v: datetime) -> datetime:
        now = datetime.now(timezone.utc)
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        if v <= now:
            raise ValueError("Renewal expiration date must be strictly in the future")
        return v


class RiskExceptionActionRequest(BaseModel):
    action: GovernanceDecision = Field(..., description="REVOKE or CLOSE")
    reason: Optional[str] = Field(default=None, description="Reason for revocation or closure")


class RiskExceptionSummary(BaseModel):
    id: Optional[int] = None
    exception_id: str
    title: str
    severity: str
    status: str
    owner: str
    asset_id: Optional[str] = None
    control_id: Optional[str] = None
    exposure_id: Optional[str] = None
    incident_id: Optional[str] = None
    risk_score: int
    requested_by: str
    approved_by: Optional[str] = None
    effective_from: datetime
    expires_at: datetime
    review_due_at: Optional[datetime] = None
    is_expired: bool = False
    is_overdue: bool = False
    created_at: datetime


class RiskExceptionDetail(BaseModel):
    id: Optional[int] = None
    exception_id: str
    title: str
    description: str
    risk_type: str
    severity: str
    status: str
    asset_id: Optional[str] = None
    control_id: Optional[str] = None
    exposure_id: Optional[str] = None
    incident_id: Optional[str] = None
    source_type: Optional[str] = None
    source_id: Optional[str] = None
    business_justification: str
    compensating_controls: Optional[str] = None
    owner: str
    requested_by: str
    approved_by: Optional[str] = None
    requested_at: datetime
    approved_at: Optional[datetime] = None
    effective_from: datetime
    expires_at: datetime
    review_due_at: Optional[datetime] = None
    risk_score: int
    policy_version: Optional[str] = "1.0.0"
    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime] = None
    is_expired: bool = False
    is_overdue: bool = False


# =============================================================================
# Control Assurance Models
# =============================================================================

class ControlAssurance(BaseModel):
    assurance_id: str
    control_id: str
    name: Optional[str] = None
    domain: Optional[str] = None
    control_type: Optional[str] = None
    assessment_period: str = "current"
    test_count: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    coverage_percentage: float = 100.0
    effectiveness_score: float = 100.0
    gap_count: int = 0
    regression_count: int = 0
    open_findings: int = 0
    open_incidents: int = 0
    open_exposures: int = 0
    last_tested_at: Optional[datetime] = None
    last_status: str = "PASS"
    risk_score: int = 0
    policy_version: Optional[str] = "1.0.0"


# =============================================================================
# Governance Risk & Factor Models
# =============================================================================

class GovernanceRiskFactor(BaseModel):
    factor: str
    weight: int
    count: int
    contribution: int
    source_ids: List[str] = Field(default_factory=list)
    description: str


class GovernanceRiskBreakdown(BaseModel):
    overall_risk_score: int = Field(ge=0, le=100)
    classification: str = Field(description="LOW, MEDIUM, HIGH, CRITICAL")
    factors: List[GovernanceRiskFactor] = Field(default_factory=list)
    raw_weighted_score: int = 0
    calculated_at: datetime


# =============================================================================
# Governance Reviews Models
# =============================================================================

class GovernanceReviewCreateRequest(BaseModel):
    review_type: GovernanceReviewType = Field(default=GovernanceReviewType.CONTROL_EFFECTIVENESS)
    scope: str = Field(default="enterprise", max_length=100)
    reviewer: Optional[str] = Field(default=None, max_length=100)
    notes: Optional[str] = None


class GovernanceReview(BaseModel):
    id: Optional[int] = None
    review_id: str
    review_type: str
    scope: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    reviewer: str
    overall_score: float
    control_coverage: float
    open_exceptions: int
    overdue_exceptions: int
    critical_exposures: int
    open_incidents: int
    policy_version: Optional[str] = "1.0.0"
    summary: str
    created_at: datetime


# =============================================================================
# Summary & Audit Event Models
# =============================================================================

class GovernanceSummary(BaseModel):
    governance_risk_score: int = 0
    governance_risk_level: str = "LOW"
    control_assurance_score: float = 100.0
    control_coverage_percentage: float = 100.0
    total_controls: int = 0
    effective_controls: int = 0
    control_gaps: int = 0
    total_exceptions: int = 0
    open_exceptions: int = 0
    approved_exceptions: int = 0
    pending_approval_exceptions: int = 0
    expired_exceptions: int = 0
    overdue_exceptions: int = 0
    critical_exposures: int = 0
    open_incidents: int = 0
    active_regressions: int = 0
    last_review_at: Optional[datetime] = None
    policy_version: str = "1.0.0"


class GovernanceEvent(BaseModel):
    event_id: str
    event_type: str
    entity_type: str
    entity_id: str
    actor: str
    description: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
