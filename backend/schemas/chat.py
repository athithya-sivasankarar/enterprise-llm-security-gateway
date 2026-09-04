from typing import List, Optional
from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=10000)
    model: str = "mock-model"


class SecurityInfo(BaseModel):
    # Input security
    pii_detected: bool
    injection_detected: bool = False
    risk_score: int
    action: str
    detected_entities: List[str] = Field(default_factory=list)
    threat_type: Optional[str] = None

    # Response / Output security
    response_risk_score: Optional[int] = None
    response_action: Optional[str] = None
    response_threat_type: Optional[str] = None

    # Semantic Caching
    cache_hit: bool = False


class ChatResponse(BaseModel):
    request_id: Optional[str] = None
    response: str
    model: str
    status: str
    security: SecurityInfo
