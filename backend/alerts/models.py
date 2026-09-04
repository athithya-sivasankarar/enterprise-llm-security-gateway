from datetime import datetime, timezone
from typing import Optional
from enum import Enum
from pydantic import BaseModel, Field


class AlertStatus(str, Enum):
    __test__ = False
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


class AlertType(str, Enum):
    __test__ = False
    CAMPAIGN_REGRESSION = "CAMPAIGN_REGRESSION"
    SECURITY_SCORE_DEGRADATION = "SECURITY_SCORE_DEGRADATION"
    CAMPAIGN_EXECUTION_ERROR = "CAMPAIGN_EXECUTION_ERROR"
    SCHEDULER_ERROR = "SCHEDULER_ERROR"
    RISK_EXCEPTION_EXPIRING = "RISK_EXCEPTION_EXPIRING"
    RISK_EXCEPTION_EXPIRED = "RISK_EXCEPTION_EXPIRED"
    OVERDUE_REMEDIATION = "OVERDUE_REMEDIATION"
    CONTROL_ASSURANCE_DEGRADED = "CONTROL_ASSURANCE_DEGRADED"
    GOVERNANCE_RISK_CRITICAL = "GOVERNANCE_RISK_CRITICAL"



class AlertSeverity(str, Enum):
    __test__ = False
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class SecurityAlert(BaseModel):
    alert_id: str
    campaign_id: str
    campaign_run_id: Optional[str] = None
    alert_type: str
    severity: str
    status: str
    title: str
    description: str
    score: Optional[float] = None
    baseline_score: Optional[float] = None
    score_delta: Optional[float] = None
    regression_count: int = 0
    policy_version: Optional[str] = "1.0.0"
    created_at: datetime
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None


class AlertSummary(BaseModel):
    total_alerts: int
    open_alerts: int
    acknowledged_alerts: int
    resolved_alerts: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int


class AlertUpdateRequest(BaseModel):
    status: str = Field(..., description="ACKNOWLEDGED or RESOLVED")
    comment: Optional[str] = None
