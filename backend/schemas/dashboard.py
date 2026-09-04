from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class DashboardSummaryResponse(BaseModel):
    total_requests: int
    allowed: int
    blocked: int
    sanitized: int
    pii_detections: int
    injection_detections: int
    response_blocks: int
    average_latency_ms: float


class ThreatStat(BaseModel):
    type: str
    count: int


class ThreatDistributionResponse(BaseModel):
    threats: List[ThreatStat]


class AuditEventItem(BaseModel):
    request_id: str
    timestamp: datetime
    user: str
    role: str
    model: str
    provider: Optional[str] = "mock"
    action: str
    risk_score: int
    pii_detected: bool
    injection_detected: bool
    threat_type: Optional[str] = None
    response_status: int
    latency_ms: float
    detected_entities: List[str] = Field(default_factory=list)
    response_risk_score: Optional[int] = None
    response_action: Optional[str] = None
    response_threat_type: Optional[str] = None
    cache_hit: bool = False


class RecentEventsResponse(BaseModel):
    events: List[AuditEventItem]


class ModelStat(BaseModel):
    model: str
    requests: int
    allowed: int
    blocked: int
    average_latency_ms: float


class ModelAnalyticsResponse(BaseModel):
    models: List[ModelStat]


class UserStat(BaseModel):
    user: str
    role: str
    requests: int
    blocked: int
    pii_detections: int
    injection_detections: int


class UserAnalyticsResponse(BaseModel):
    users: List[UserStat]


class TimelinePoint(BaseModel):
    timestamp: str
    requests: int
    allowed: int
    blocked: int
    sanitized: int


class TimelineResponse(BaseModel):
    timeline: List[TimelinePoint]


class CacheStatsResponse(BaseModel):
    enabled: bool
    hits: int
    misses: int
    total_cache_requests: int
    hit_rate: float


class ProviderStat(BaseModel):
    provider: str
    requests: int
    cache_hits: int
    blocked: int
    average_latency_ms: float


class ProviderAnalyticsResponse(BaseModel):
    providers: List[ProviderStat]


class ProvidersHealthResponse(BaseModel):
    providers: Dict[str, Dict[str, bool]]


class ObservabilityTelemetryResponse(BaseModel):
    requests_per_minute: float
    error_rate: float
    blocked_requests: int
    pii_detections: int
    prompt_injections: int
    response_blocks: int
    provider_errors: int
    cache_hit_rate: float
    average_latency_ms: float
    p95_latency_ms: float
