from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field


class CampaignStatus(str, Enum):
    __test__ = False
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    ARCHIVED = "ARCHIVED"


class CampaignCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    category_filter: Optional[List[str]] = Field(default_factory=list)
    schedule_enabled: Optional[bool] = False
    schedule_interval: Optional[str] = "daily"
    policy_version: Optional[str] = "1.0.0"
    baseline_run_id: Optional[str] = None


class CampaignUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    category_filter: Optional[List[str]] = None
    schedule_enabled: Optional[bool] = None
    schedule_interval: Optional[str] = None
    status: Optional[str] = None
    baseline_run_id: Optional[str] = None


class RegressionItem(BaseModel):
    regression_id: str
    campaign_run_id: str
    campaign_id: str
    test_id: str
    category: str
    severity: str
    previous_status: str
    current_status: str
    previous_score: Optional[float] = None
    current_score: Optional[float] = None
    score_delta: Optional[float] = None
    policy_version: Optional[str] = "1.0.0"
    baseline_run_id: Optional[str] = None
    current_run_id: Optional[str] = None
    description: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BaselineComparisonResult(BaseModel):
    campaign_id: str
    baseline_run_id: Optional[str] = None
    current_run_id: str
    baseline_score: Optional[float] = None
    current_score: float
    score_delta: float
    regression_detected: bool
    new_failures: List[str] = Field(default_factory=list)
    new_errors: List[str] = Field(default_factory=list)
    resolved_failures: List[str] = Field(default_factory=list)
    categories_regressed: List[str] = Field(default_factory=list)
    category_deltas: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    regressions: List[RegressionItem] = Field(default_factory=list)
    added_tests: List[str] = Field(default_factory=list)
    removed_tests: List[str] = Field(default_factory=list)


class CampaignSummary(BaseModel):
    campaign_id: str
    name: str
    description: Optional[str] = None
    status: str
    created_by: str
    created_at: datetime
    updated_at: datetime
    last_run_id: Optional[str] = None
    schedule_enabled: bool = False
    schedule_interval: Optional[str] = None
    category_filter: List[str] = Field(default_factory=list)
    policy_version: str = "1.0.0"
    baseline_run_id: Optional[str] = None
    latest_score: Optional[float] = None
    baseline_score: Optional[float] = None
    score_delta: Optional[float] = None
    regression_detected: Optional[bool] = None


class CampaignRunSummary(BaseModel):
    campaign_run_id: str
    campaign_id: str
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
    baseline_score: Optional[float] = None
    score_delta: Optional[float] = None
    regression_detected: bool = False
    created_by: str
    policy_version: str = "1.0.0"


class SetBaselineRequest(BaseModel):
    run_id: str
