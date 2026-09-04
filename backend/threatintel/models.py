from enum import Enum
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ThreatIndicatorType(str, Enum):
    CVE = "CVE"
    CWE = "CWE"
    ATTACK_TECHNIQUE = "ATTACK_TECHNIQUE"
    ATLAS_TECHNIQUE = "ATLAS_TECHNIQUE"
    OWASP_CATEGORY = "OWASP_CATEGORY"
    CONTROL_WEAKNESS = "CONTROL_WEAKNESS"
    THREAT_PATTERN = "THREAT_PATTERN"


class ThreatSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ThreatIntelItem(BaseModel):
    intel_id: str
    source: str
    indicator_type: str
    indicator: str
    category: str
    severity: str = "HIGH"
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    description: str
    first_seen_at: datetime
    last_seen_at: datetime
    expires_at: Optional[datetime] = None
    status: str = "ACTIVE"
    created_at: datetime


class ThreatIntelCreateRequest(BaseModel):
    source: str = "COMMUNITY"
    indicator_type: str
    indicator: str
    category: str
    severity: str = "HIGH"
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    description: str


class ThreatIntelSummary(BaseModel):
    total_indicators: int = 0
    active_indicators: int = 0
    critical_indicators: int = 0
    high_indicators: int = 0
    categories_covered: int = 0
    sources: List[str] = Field(default_factory=list)


class ThreatIntelMatch(BaseModel):
    intel_id: str
    indicator: str
    indicator_type: str
    category: str
    severity: str
    confidence: float
    relevance_score: int = Field(default=0, ge=0, le=100)
    description: str
    matched_target_type: str  # TEST, FINDING, REGRESSION, INCIDENT, ASSET, CONTROL
    matched_target_id: str
    match_reason: str


class ThreatIntelMatchRequest(BaseModel):
    category: Optional[str] = None
    test_id: Optional[str] = None
    finding_id: Optional[str] = None
    incident_id: Optional[str] = None
    asset_id: Optional[str] = None


class ThreatIntelSearchRequest(BaseModel):
    category: Optional[str] = None
    indicator_type: Optional[str] = None
    severity: Optional[str] = None
    query: Optional[str] = None
    limit: int = 50
