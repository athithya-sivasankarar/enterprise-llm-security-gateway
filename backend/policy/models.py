from datetime import datetime
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class RateLimitPolicy(BaseModel):
    requests: int = Field(default=10, ge=1, description="Maximum requests permitted per window")
    window_seconds: int = Field(default=60, ge=1, description="Sliding window duration in seconds")


class InputSecurityPolicy(BaseModel):
    dlp_enabled: bool = Field(default=True, description="Enable Presidio DLP PII inspection and sanitization")
    prompt_injection_enabled: bool = Field(default=True, description="Enable prompt injection and jailbreak detection")
    block_threshold: int = Field(default=60, ge=60, le=100, description="Risk score threshold to block prompt injection (min 60)")


class ResponseSecurityPolicy(BaseModel):
    enabled: bool = Field(default=True, description="Enable response output security inspection")
    block_threshold: int = Field(default=80, ge=60, le=100, description="Risk score threshold to block responses (min 60)")
    sanitize_threshold: int = Field(default=30, ge=0, le=100, description="Risk score threshold to sanitize response PII")


class CachePolicy(BaseModel):
    enabled: bool = Field(default=True, description="Enable Redis semantic caching")
    ttl_seconds: int = Field(default=300, ge=1, le=86400, description="Cache entry TTL in seconds")


class RolePolicy(BaseModel):
    allowed_models: List[str] = Field(default_factory=list, description="Authorized models for role")
    dashboard_access: bool = Field(default=False, description="Permission to access SOC dashboard and analytics")


class ProviderConfig(BaseModel):
    enabled: bool = Field(default=True, description="Enable provider routing")
    allowed_models: List[str] = Field(default_factory=list, description="Models handled by this provider")
    timeout_seconds: int = Field(default=30, ge=1, le=120, description="Maximum provider timeout in seconds")


class SecurityPolicySchema(BaseModel):
    """
    Centralized, strongly typed security policy configuration.
    """
    policy_version: str = Field(..., pattern=r"^\d+\.\d+\.\d+$", description="Semantic version string (e.g. 1.0.0)")
    rate_limit: RateLimitPolicy = Field(default_factory=RateLimitPolicy)
    input_security: InputSecurityPolicy = Field(default_factory=InputSecurityPolicy)
    response_security: ResponseSecurityPolicy = Field(default_factory=ResponseSecurityPolicy)
    cache: CachePolicy = Field(default_factory=CachePolicy)
    rbac: Dict[str, RolePolicy] = Field(default_factory=dict)
    providers: Dict[str, ProviderConfig] = Field(default_factory=dict)


class PolicyCreateRequest(BaseModel):
    policy_version: str = Field(..., pattern=r"^\d+\.\d+\.\d+$")
    name: str = Field(..., min_length=3, max_length=100)
    description: Optional[str] = Field(default=None, max_length=255)
    policy: SecurityPolicySchema


class PolicyValidationResponse(BaseModel):
    valid: bool
    policy_version: str
    errors: List[str] = Field(default_factory=list)


class PolicySummaryItem(BaseModel):
    id: Optional[int] = None
    policy_version: str
    name: str
    description: Optional[str] = None
    is_active: bool
    created_by: str
    created_at: datetime
    updated_at: datetime


class PolicyHistoryResponse(BaseModel):
    policies: List[PolicySummaryItem]
    total: int


class PolicyActiveResponse(BaseModel):
    policy_version: str
    name: str
    description: Optional[str] = None
    is_active: bool
    policy: SecurityPolicySchema
    updated_at: datetime
    updated_by: str
