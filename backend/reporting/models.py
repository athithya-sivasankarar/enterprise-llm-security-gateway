from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field


class ReportType(str, Enum):
    __test__ = False
    CAMPAIGN = "CAMPAIGN"
    SECURITY_VALIDATION = "SECURITY_VALIDATION"
    REGRESSION = "REGRESSION"
    EXECUTIVE = "EXECUTIVE"
    COMPLIANCE = "COMPLIANCE"
    GOVERNANCE = "GOVERNANCE"



class ReportStatus(str, Enum):
    __test__ = False
    GENERATING = "GENERATING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ReportCreateRequest(BaseModel):
    report_type: str = Field(default="CAMPAIGN", description="CAMPAIGN, SECURITY_VALIDATION, REGRESSION, EXECUTIVE, COMPLIANCE")
    title: Optional[str] = Field(default=None, description="Optional custom report title")
    description: Optional[str] = Field(default=None, description="Optional report scope or background")
    campaign_id: Optional[str] = Field(default=None, description="Associated Campaign ID")
    campaign_run_id: Optional[str] = Field(default=None, description="Specific Campaign Run ID")
    run_id: Optional[str] = Field(default=None, description="Specific Validation Run ID")


class ReportFinding(BaseModel):
    finding_id: str
    test_id: str
    category: str
    severity: str
    title: str
    description: str
    expected_behavior: str
    actual_behavior: str
    endpoint: str
    policy_version: str = "1.0.0"
    timestamp: datetime


class EvidenceItem(BaseModel):
    evidence_id: str
    test_id: str
    category: str
    severity: str
    evidence_type: str
    expected_behavior: str
    actual_behavior: str
    security_control: str
    endpoint: str
    status: str
    policy_version: str = "1.0.0"
    timestamp: datetime


class CategoryResult(BaseModel):
    category: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    error_tests: int
    score: float
    status: str


class ComplianceMapping(BaseModel):
    framework: str
    control_id: str
    control_name: str
    gateway_controls: List[str]
    evidence_count: int
    coverage_status: str
    disclaimer: str = "Compliance mappings provide security-control evidence and assessment coverage only. They do not constitute certification, legal compliance, or an independent audit."


class ExecutiveSummary(BaseModel):
    security_score: float
    baseline_score: Optional[float] = None
    score_delta: Optional[float] = None
    security_posture: str  # SECURE, DEGRADED, CRITICAL
    total_tests: int
    passed_tests: int
    failed_tests: int
    error_tests: int
    skipped_tests: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    regression_count: int
    open_alerts_count: int
    policy_version: str = "1.0.0"
    generated_at: datetime


class ReportSummary(BaseModel):
    report_id: str
    report_type: str
    title: str
    description: Optional[str] = None
    status: str
    created_by: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    campaign_id: Optional[str] = None
    campaign_run_id: Optional[str] = None
    security_score: float
    baseline_score: Optional[float] = None
    score_delta: Optional[float] = None
    regression_count: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    policy_version: Optional[str] = "1.0.0"
    report_version: str = "1.0.0"
    report_hash: Optional[str] = None


class SecurityReport(BaseModel):
    report_id: str
    report_type: str
    title: str
    description: Optional[str] = None
    status: str
    created_by: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    campaign_id: Optional[str] = None
    campaign_run_id: Optional[str] = None
    executive_summary: ExecutiveSummary
    category_results: List[CategoryResult] = []
    findings: List[ReportFinding] = []
    regressions: List[Dict[str, Any]] = []
    compliance_mappings: List[ComplianceMapping] = []
    evidence_count: int = 0
    policy_version: str = "1.0.0"
    report_version: str = "1.0.0"
    report_hash: Optional[str] = None
    methodology: str
    limitations: str
    compliance_disclaimer: str = "Compliance mappings provide security-control evidence and assessment coverage only. They do not constitute certification, legal compliance, or an independent audit."


class ReportExportRequest(BaseModel):
    format: str = Field(default="json", description="json, markdown, csv, pdf")
