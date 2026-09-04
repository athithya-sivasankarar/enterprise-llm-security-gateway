from enum import Enum
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class AssetType(str, Enum):
    APPLICATION = "APPLICATION"
    API = "API"
    ENDPOINT = "ENDPOINT"
    LLM_MODEL = "LLM_MODEL"
    LLM_PROVIDER = "LLM_PROVIDER"
    DATABASE = "DATABASE"
    CACHE = "CACHE"
    SECURITY_CONTROL = "SECURITY_CONTROL"
    KUBERNETES_SERVICE = "KUBERNETES_SERVICE"


class AssetCriticality(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class SecurityAsset(BaseModel):
    asset_id: str
    asset_type: str
    name: str
    description: Optional[str] = None
    environment: str = "production"
    endpoint: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    owner: str = "security-team"
    criticality: str = "HIGH"
    status: str = "ACTIVE"
    discovered_at: datetime
    updated_at: datetime
    last_tested_at: Optional[datetime] = None
    last_security_score: Optional[float] = None
    risk_score: int = Field(default=0, ge=0, le=100)
    policy_version: Optional[str] = "1.0.0"


class AssetCreateRequest(BaseModel):
    asset_type: str
    name: str
    description: Optional[str] = None
    environment: str = "production"
    endpoint: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    owner: str = "security-team"
    criticality: str = "HIGH"


class AssetUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    environment: Optional[str] = None
    endpoint: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    owner: Optional[str] = None
    criticality: Optional[str] = None
    status: Optional[str] = None


class AssetSummary(BaseModel):
    total_assets: int = 0
    critical_assets: int = 0
    high_assets: int = 0
    medium_assets: int = 0
    low_assets: int = 0
    active_assets: int = 0
    covered_assets_count: int = 0
    uncovered_assets_count: int = 0
    overall_coverage_pct: float = 0.0
    avg_asset_risk_score: float = 0.0


class AttackSurfaceNode(BaseModel):
    id: str
    name: str
    type: str
    layer: str  # CLIENT, GATEWAY_API, SECURITY_PIPELINE, LLM_PROVIDER, STORAGE_INFRA
    criticality: str
    risk_score: int
    status: str
    coverage_pct: float = 100.0


class AttackSurfaceEdge(BaseModel):
    source: str
    target: str
    relationship: str
    security_control: Optional[str] = None


class AttackSurfaceGraph(BaseModel):
    nodes: List[AttackSurfaceNode] = Field(default_factory=list)
    edges: List[AttackSurfaceEdge] = Field(default_factory=list)
    total_assets: int = 0
    critical_assets: int = 0
    avg_risk_score: float = 0.0
    dataflow_layers: List[str] = Field(default_factory=list)


class AssetCoverageDetail(BaseModel):
    asset: SecurityAsset
    controls_mapped: List[str] = Field(default_factory=list)
    tests_mapped: List[str] = Field(default_factory=list)
    findings_count: int = 0
    active_incidents_count: int = 0
    exposures_count: int = 0
    coverage_pct: float = 0.0
    risk_score: int = 0
