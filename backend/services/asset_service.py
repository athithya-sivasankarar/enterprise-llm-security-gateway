import uuid
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from backend.db.models import (
    SecurityAssetModel,
    SecurityAssetFindingModel,
    SecurityExposureModel,
    SecurityTestResultModel,
    SecurityIncidentModel
)
from backend.attack_surface.models import (
    SecurityAsset,
    AssetCreateRequest,
    AssetUpdateRequest,
    AssetSummary,
    AssetCoverageDetail,
    AttackSurfaceGraph
)
from backend.attack_surface.mapper import build_logical_attack_surface_graph
from backend.attack_surface.coverage import calculate_asset_multidimensional_coverage
from backend.observability.metrics import (
    record_asset_registered_metric,
    record_asset_critical_metric
)
from backend.observability.logging import log_security_event

logger = logging.getLogger(__name__)

# Standard Gateway Architectural Assets (Logical Discovery only - no network probing)
STANDARD_GATEWAY_ASSETS: List[Dict[str, Any]] = [
    {
        "asset_id": "ast-fe-dashboard",
        "asset_type": "APPLICATION",
        "name": "SOC Real-Time Security Dashboard",
        "description": "React SPA dashboard for SOC analysts and security monitoring.",
        "endpoint": "/",
        "provider": "system",
        "criticality": "HIGH",
        "status": "ACTIVE"
    },
    {
        "asset_id": "ast-api-chat",
        "asset_type": "API",
        "name": "Enterprise LLM Gateway Chat API",
        "description": "Primary high-throughput endpoint with DLP, RBAC, Rate Limiting, and Injection Defense.",
        "endpoint": "/api/chat",
        "provider": "system",
        "criticality": "CRITICAL",
        "status": "ACTIVE"
    },
    {
        "asset_id": "ast-llm-mock",
        "asset_type": "LLM_MODEL",
        "name": "Mock Validation LLM Model",
        "description": "Safe, offline deterministic mock provider model for automated red-team validation.",
        "endpoint": "/api/chat",
        "provider": "mock",
        "model": "mock-model",
        "criticality": "HIGH",
        "status": "ACTIVE"
    },
    {
        "asset_id": "ast-llm-gpt4o",
        "asset_type": "LLM_MODEL",
        "name": "OpenAI GPT-4o Mini Enterprise Deployment",
        "description": "Production LLM model deployment for general enterprise workflows.",
        "endpoint": "/api/chat",
        "provider": "openai",
        "model": "gpt-4o-mini",
        "criticality": "CRITICAL",
        "status": "ACTIVE"
    },
    {
        "asset_id": "ast-llm-claude",
        "asset_type": "LLM_MODEL",
        "name": "Anthropic Claude 3.5 Sonnet Deployment",
        "description": "High-capability reasoning and coding model integration.",
        "endpoint": "/api/chat",
        "provider": "anthropic",
        "model": "claude-3-5-sonnet-latest",
        "criticality": "CRITICAL",
        "status": "ACTIVE"
    },
    {
        "asset_id": "ast-db-postgres",
        "asset_type": "DATABASE",
        "name": "Enterprise Security PostgreSQL DB",
        "description": "Encrypted persistent database storing audit trails, policies, campaigns, reports, and incidents.",
        "endpoint": "postgres:5432",
        "provider": "postgres",
        "criticality": "CRITICAL",
        "status": "ACTIVE"
    },
    {
        "asset_id": "ast-cache-redis",
        "asset_type": "CACHE",
        "name": "Enterprise Redis Semantic Cache & Rate Limiter",
        "description": "In-memory store providing sliding-window rate limiting and semantic prompt caching.",
        "endpoint": "redis:6379",
        "provider": "redis",
        "criticality": "HIGH",
        "status": "ACTIVE"
    },
    {
        "asset_id": "ast-obs-prometheus",
        "asset_type": "KUBERNETES_SERVICE",
        "name": "Prometheus Telemetry & Metrics Service",
        "description": "Low-cardinality time-series metrics aggregator for SOC alerting.",
        "endpoint": "/metrics",
        "provider": "system",
        "criticality": "MEDIUM",
        "status": "ACTIVE"
    }
]


def _to_security_asset(m: SecurityAssetModel) -> SecurityAsset:
    return SecurityAsset(
        asset_id=m.asset_id,
        asset_type=m.asset_type,
        name=m.name,
        description=m.description,
        environment=m.environment,
        endpoint=m.endpoint,
        provider=m.provider,
        model=m.model,
        owner=m.owner,
        criticality=m.criticality,
        status=m.status,
        discovered_at=m.discovered_at,
        updated_at=m.updated_at,
        last_tested_at=m.last_tested_at,
        last_security_score=m.last_security_score,
        risk_score=m.risk_score,
        policy_version=m.policy_version
    )


async def init_default_assets_if_empty(db: AsyncSession) -> None:
    """
    Bootstrap standard logical gateway assets idempotently if missing.
    """
    try:
        stmt = select(SecurityAssetModel.asset_id)
        res = await db.execute(stmt)
        existing_ids = set(res.scalars().all())
        now = datetime.now(timezone.utc)
        added = False
        for ast in STANDARD_GATEWAY_ASSETS:
            if ast["asset_id"] not in existing_ids:
                row = SecurityAssetModel(
                    asset_id=ast["asset_id"],
                    asset_type=ast["asset_type"],
                    name=ast["name"],
                    description=ast["description"],
                    environment="production",
                    endpoint=ast.get("endpoint"),
                    provider=ast.get("provider"),
                    model=ast.get("model"),
                    owner="security-team",
                    criticality=ast.get("criticality", "HIGH"),
                    status=ast.get("status", "ACTIVE"),
                    discovered_at=now,
                    updated_at=now,
                    risk_score=15 if ast.get("criticality") == "CRITICAL" else 5,
                    policy_version="1.0.0"
                )
                db.add(row)
                added = True
        if added:
            await db.commit()
            logger.info("Initialized standard gateway assets.")
    except Exception as e:
        logger.warning(f"Failed to bootstrap security assets: {e}")


async def register_asset(
    db: AsyncSession,
    req: AssetCreateRequest,
    user: str
) -> SecurityAsset:
    """
    Register a new AI/LLM asset (Admin/Analyst only).
    """
    asset_id = f"ast-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)

    # Initial risk score based on criticality
    crit_risk = 25 if req.criticality.upper() == "CRITICAL" else 15 if req.criticality.upper() == "HIGH" else 5

    row = SecurityAssetModel(
        asset_id=asset_id,
        asset_type=req.asset_type.upper(),
        name=req.name,
        description=req.description,
        environment=req.environment,
        endpoint=req.endpoint,
        provider=req.provider,
        model=req.model,
        owner=req.owner,
        criticality=req.criticality.upper(),
        status="ACTIVE",
        discovered_at=now,
        updated_at=now,
        risk_score=crit_risk,
        policy_version="1.0.0"
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)

    record_asset_registered_metric(row.asset_type)
    if row.criticality == "CRITICAL":
        record_asset_critical_metric()

    log_security_event(
        event_type="SECURITY_ASSET_REGISTERED",
        request_id=f"ast-reg-{asset_id}",
        action="ALLOW",
        response_status=201,
        user=user,
        role="security-analyst",
        threat_type=row.asset_type
    )

    return _to_security_asset(row)


async def get_asset(db: AsyncSession, asset_id: str) -> SecurityAsset:
    await init_default_assets_if_empty(db)
    stmt = select(SecurityAssetModel).where(SecurityAssetModel.asset_id == asset_id)
    res = await db.execute(stmt)
    row = res.scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security asset '{asset_id}' not found."
        )
    return _to_security_asset(row)


async def list_assets(
    db: AsyncSession,
    asset_type: Optional[str] = None,
    criticality: Optional[str] = None,
    status_filter: Optional[str] = None
) -> List[SecurityAsset]:
    await init_default_assets_if_empty(db)
    query = select(SecurityAssetModel).order_by(desc(SecurityAssetModel.risk_score), SecurityAssetModel.name)
    if asset_type:
        query = query.where(SecurityAssetModel.asset_type == asset_type.upper())
    if criticality:
        query = query.where(SecurityAssetModel.criticality == criticality.upper())
    if status_filter:
        query = query.where(SecurityAssetModel.status == status_filter.upper())

    res = await db.execute(query)
    rows = res.scalars().all()
    return [_to_security_asset(r) for r in rows]


async def update_asset(
    db: AsyncSession,
    asset_id: str,
    req: AssetUpdateRequest,
    user: str
) -> SecurityAsset:
    await init_default_assets_if_empty(db)
    stmt = select(SecurityAssetModel).where(SecurityAssetModel.asset_id == asset_id)
    res = await db.execute(stmt)
    row = res.scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security asset '{asset_id}' not found."
        )

    if req.name is not None:
        row.name = req.name
    if req.description is not None:
        row.description = req.description
    if req.environment is not None:
        row.environment = req.environment
    if req.endpoint is not None:
        row.endpoint = req.endpoint
    if req.provider is not None:
        row.provider = req.provider
    if req.model is not None:
        row.model = req.model
    if req.owner is not None:
        row.owner = req.owner
    if req.criticality is not None:
        row.criticality = req.criticality.upper()
    if req.status is not None:
        row.status = req.status.upper()

    row.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(row)

    log_security_event(
        event_type="SECURITY_ASSET_UPDATED",
        request_id=f"ast-up-{asset_id}",
        action="ALLOW",
        response_status=200,
        user=user,
        role="security-analyst",
        threat_type=row.asset_type
    )

    return _to_security_asset(row)


async def get_asset_coverage(
    db: AsyncSession,
    asset_id: str
) -> AssetCoverageDetail:
    """
    Calculate multidimensional coverage for an asset.
    """
    asset = await get_asset(db, asset_id)

    # Fetch latest test results
    stmt_t = select(SecurityTestResultModel).limit(200)
    res_t = await db.execute(stmt_t)
    test_map = {r.test_id: r.status for r in res_t.scalars().all()}

    # Fetch findings count
    stmt_f = select(func.count(SecurityAssetFindingModel.id)).where(
        SecurityAssetFindingModel.asset_id == asset_id,
        SecurityAssetFindingModel.status == "OPEN"
    )
    res_f = await db.execute(stmt_f)
    f_count = res_f.scalar() or 0

    # Fetch active incidents count
    stmt_i = select(func.count(SecurityIncidentModel.id)).where(
        SecurityIncidentModel.status.in_(["OPEN", "INVESTIGATING"])
    )
    res_i = await db.execute(stmt_i)
    i_count = res_i.scalar() or 0

    # Fetch exposures count
    stmt_e = select(func.count(SecurityExposureModel.id)).where(
        SecurityExposureModel.asset_id == asset_id,
        SecurityExposureModel.status == "OPEN"
    )
    res_e = await db.execute(stmt_e)
    e_count = res_e.scalar() or 0

    return calculate_asset_multidimensional_coverage(
        asset=asset,
        test_results_map=test_map,
        findings_count=f_count,
        active_incidents_count=i_count,
        exposures_count=e_count
    )


async def get_asset_summary(db: AsyncSession) -> AssetSummary:
    await init_default_assets_if_empty(db)
    stmt = select(SecurityAssetModel)
    res = await db.execute(stmt)
    all_assets = res.scalars().all()

    total = len(all_assets)
    crit = sum(1 for a in all_assets if a.criticality == "CRITICAL")
    high = sum(1 for a in all_assets if a.criticality == "HIGH")
    med = sum(1 for a in all_assets if a.criticality == "MEDIUM")
    low = sum(1 for a in all_assets if a.criticality == "LOW")
    active = sum(1 for a in all_assets if a.status == "ACTIVE")
    avg_risk = sum(a.risk_score for a in all_assets) / total if total > 0 else 0.0

    return AssetSummary(
        total_assets=total,
        critical_assets=crit,
        high_assets=high,
        medium_assets=med,
        low_assets=low,
        active_assets=active,
        covered_assets_count=total,
        uncovered_assets_count=0,
        overall_coverage_pct=100.0,
        avg_asset_risk_score=round(avg_risk, 1)
    )


async def get_attack_surface_graph(db: AsyncSession) -> AttackSurfaceGraph:
    """
    Generate logical attack surface dataflow graph.
    """
    assets = await list_assets(db)
    asset_dicts = [a.model_dump() for a in assets]
    return build_logical_attack_surface_graph(asset_dicts)
