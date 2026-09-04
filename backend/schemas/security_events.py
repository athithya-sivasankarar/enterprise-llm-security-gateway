import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class SecurityEventItem(BaseModel):
    """
    Normalized SIEM-ready security event schema.
    Contains metadata and threat signals only — never contains raw prompts or API keys.
    """
    event_id: str
    timestamp: datetime.datetime
    request_id: str
    event_type: str  # AUTH_FAILURE, MODEL_ACCESS_DENIED, RATE_LIMIT_BLOCK, PII_DETECTED, PROMPT_INJECTION, SECRET_LEAKAGE, UNSAFE_CONTENT, SECURITY_AUDIT
    severity: str    # LOW, MEDIUM, HIGH, CRITICAL
    user: str
    role: str
    model: str
    provider: str
    action: str      # ALLOW, SANITIZE, BLOCK
    risk_score: int
    threat_type: Optional[str] = None
    response_status: int
    latency_ms: Optional[float] = None
    cache_hit: bool = False
    detected_entities: List[str] = Field(default_factory=list)


class SecurityEventsResponse(BaseModel):
    """
    Paginated SIEM export response.
    """
    events: List[SecurityEventItem]
    total: int
