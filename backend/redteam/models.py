from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from backend.redteam.categories import TestCategory, SeverityLevel, TestStatus


class SecurityTestCase(BaseModel):
    """
    Specification for a deterministic, safe security validation test case.
    """
    test_id: str
    name: str
    category: TestCategory
    description: str
    severity: SeverityLevel = SeverityLevel.MEDIUM
    
    # Request configuration
    endpoint: str = "/api/chat"
    method: str = "POST"
    api_key_role: Optional[str] = "admin"  # "admin", "analyst", "developer", "none", "invalid"
    custom_headers: Optional[Dict[str, str]] = None
    
    # Chat payload configuration (defaults to mock-model)
    model: str = "mock-model"
    prompt: Optional[str] = None
    custom_payload: Optional[Dict[str, Any]] = None
    
    # Expected gateway responses / security behaviors
    expected_status: int = 200
    expected_action: Optional[str] = None  # "ALLOW", "SANITIZE", "BLOCK", "ERROR"
    expected_threat_type: Optional[str] = None
    expected_pii_detected: Optional[bool] = None
    expected_cache_hit: Optional[bool] = None
    
    # Assertion mode / custom validation function key
    assertion_type: str = "standard_gateway_check"  # e.g., "standard_gateway_check", "rbac_dashboard_check", "rate_limit_sequence", "cache_isolation_sequence", "policy_eval_check"


class SecurityTestResult(BaseModel):
    """
    Result of an individual test case evaluation.
    """
    run_id: str
    test_id: str
    category: str
    status: str  # PASS, FAIL, ERROR, SKIPPED
    severity: str
    expected_action: Optional[str] = None
    actual_action: Optional[str] = None
    expected_status: Optional[int] = None
    actual_status: Optional[int] = None
    threat_type: Optional[str] = None
    latency_ms: float = 0.0
    policy_version: str = "1.0.0"
    error_message: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SecurityTestFinding(BaseModel):
    """
    Normalized security finding generated when a test fails.
    """
    finding_id: str
    run_id: str
    test_id: str
    category: str
    severity: str
    title: str
    description: str
    expected_behavior: str
    actual_behavior: str
    endpoint: str = "/api/chat"
    policy_version: str = "1.0.0"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CategorySummary(BaseModel):
    """
    Summary breakdown of security test outcomes per category.
    """
    category: str
    total: int
    passed: int
    failed: int
    errors: int
    skipped: int
    pass_rate: float


class SecurityTestRunSummary(BaseModel):
    """
    High-level summary of a security validation run.
    """
    run_id: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    error_tests: int
    skipped_tests: int
    security_score: float
    policy_version: str
    created_by: str


class SecurityReport(BaseModel):
    """
    Full security validation and adversarial test report.
    Never exposes raw secrets, credentials, or production PII.
    """
    run_id: str
    status: str
    security_score: float
    policy_version: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    created_by: str
    summary: Dict[str, Any]
    category_summaries: List[CategorySummary]
    findings: List[SecurityTestFinding]
    test_results: List[SecurityTestResult]


class RunSecurityTestsRequest(BaseModel):
    """
    Request model for triggering a security validation run.
    """
    categories: Optional[List[str]] = None
