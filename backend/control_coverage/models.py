from enum import Enum
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ControlDomain(str, Enum):
    AUTHENTICATION = "AUTHENTICATION"
    RBAC = "RBAC"
    RATE_LIMITING = "RATE_LIMITING"
    INPUT_DLP = "INPUT_DLP"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    SYSTEM_PROMPT_EXTRACTION = "SYSTEM_PROMPT_EXTRACTION"
    SECRET_LEAKAGE = "SECRET_LEAKAGE"
    UNSAFE_CONTENT = "UNSAFE_CONTENT"
    RESPONSE_PII = "RESPONSE_PII"
    CACHE_ISOLATION = "CACHE_ISOLATION"
    POLICY = "POLICY"
    AUDIT = "AUDIT"
    OBSERVABILITY = "OBSERVABILITY"


class ControlStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    REGRESSION = "REGRESSION"
    NOT_TESTED = "NOT_TESTED"
    DISABLED = "DISABLED"


class ControlGapType(str, Enum):
    CONTROL_NOT_TESTED = "CONTROL_NOT_TESTED"
    CONTROL_PARTIALLY_COVERED = "CONTROL_PARTIALLY_COVERED"
    CONTROL_FAILING = "CONTROL_FAILING"
    CONTROL_REGRESSION = "CONTROL_REGRESSION"
    CONTROL_DISABLED = "CONTROL_DISABLED"


class SecurityControlItem(BaseModel):
    control_id: str
    name: str
    description: str
    domain: str
    control_type: str = "PREVENTIVE"
    enabled: bool = True
    implementation_status: str = "IMPLEMENTED"
    coverage_percentage: float = 100.0
    last_tested_at: Optional[datetime] = None
    last_test_status: Optional[str] = "PASS"
    policy_version: Optional[str] = "1.0.0"


class ControlCoverageMatrixItem(BaseModel):
    domain: str
    control_id: str
    name: str
    control_type: str = "PREVENTIVE"
    tests_mapped: List[str] = Field(default_factory=list)
    tests_executed: int = 0
    tests_passed: int = 0
    coverage_pct: float = 0.0
    pass_rate_pct: float = 0.0
    status: str = "NOT_TESTED"
    last_tested_at: Optional[datetime] = None


class ControlGapItem(BaseModel):
    control_id: str
    domain: str
    gap_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    recommendation: str


class ControlCoverageSummary(BaseModel):
    total_controls: int = 0
    tested_controls: int = 0
    passing_controls: int = 0
    failing_controls: int = 0
    regression_controls: int = 0
    disabled_controls: int = 0
    overall_coverage_pct: float = 0.0
    overall_pass_pct: float = 0.0
    control_gaps_count: int = 0
    matrix: List[ControlCoverageMatrixItem] = Field(default_factory=list)
    gaps: List[ControlGapItem] = Field(default_factory=list)
