import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy import select, func, desc, case, literal_column, and_
from sqlalchemy.ext.asyncio import AsyncSession


from backend.db.database import get_db
from backend.db.models import AuditLog
from backend.security.rbac import require_dashboard_access
from backend.services.semantic_cache import is_cache_enabled
from backend.providers import get_providers_health
from backend.schemas.dashboard import (
    DashboardSummaryResponse,
    ThreatDistributionResponse,
    ThreatStat,
    RecentEventsResponse,
    AuditEventItem,
    ModelAnalyticsResponse,
    ModelStat,
    UserAnalyticsResponse,
    UserStat,
    TimelineResponse,
    TimelinePoint,
    CacheStatsResponse,
    ProviderAnalyticsResponse,
    ProviderStat,
    ProvidersHealthResponse,
    ObservabilityTelemetryResponse
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api",
    tags=["SOC Dashboard & Analytics"]
)


@router.get("/dashboard/summary", response_model=DashboardSummaryResponse)
async def get_dashboard_summary(
    user: dict = Depends(require_dashboard_access),
    db: AsyncSession = Depends(get_db)
):
    """
    Return aggregated KPI metrics for the SOC Dashboard calculated directly from PostgreSQL audit_logs.
    """
    try:
        stmt = select(
            func.count(AuditLog.id).label("total_requests"),
            func.count().filter(AuditLog.action == "ALLOW").label("allowed"),
            func.count().filter(AuditLog.action == "BLOCK").label("blocked"),
            func.count().filter(AuditLog.action == "SANITIZE").label("sanitized"),
            func.count().filter(AuditLog.pii_detected.is_(True)).label("pii_detections"),
            func.count().filter(AuditLog.injection_detected.is_(True)).label("injection_detections"),
            func.count().filter(AuditLog.response_action == "BLOCK").label("response_blocks"),
            func.coalesce(func.avg(AuditLog.latency_ms), 0.0).label("average_latency_ms")
        )
        result = await db.execute(stmt)
        row = result.one()

        return DashboardSummaryResponse(
            total_requests=row.total_requests or 0,
            allowed=row.allowed or 0,
            blocked=row.blocked or 0,
            sanitized=row.sanitized or 0,
            pii_detections=row.pii_detections or 0,
            injection_detections=row.injection_detections or 0,
            response_blocks=row.response_blocks or 0,
            average_latency_ms=round(float(row.average_latency_ms or 0.0), 2)
        )
    except Exception as exc:
        logger.error("Failed to retrieve dashboard summary: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve dashboard metrics"
        ) from exc


@router.get("/dashboard/threats", response_model=ThreatDistributionResponse)
async def get_threat_distribution(
    user: dict = Depends(require_dashboard_access),
    db: AsyncSession = Depends(get_db)
):
    """
    Return aggregated threat counts across prompt injections, jailbreaks, secret leakages, and RBAC blocks.
    """
    try:
        threat_counts = {}

        # 1. Query input threat types
        stmt_input = select(
            AuditLog.threat_type,
            func.count(AuditLog.id)
        ).where(
            AuditLog.threat_type.isnot(None)
        ).group_by(AuditLog.threat_type)

        res_input = await db.execute(stmt_input)
        for t_type, count in res_input.all():
            if t_type:
                threat_counts[t_type] = threat_counts.get(t_type, 0) + count

        # 2. Query response threat types (Secret leakage, unsafe content)
        stmt_resp = select(
            AuditLog.response_threat_type,
            func.count(AuditLog.id)
        ).where(
            AuditLog.response_threat_type.isnot(None)
        ).group_by(AuditLog.response_threat_type)

        res_resp = await db.execute(stmt_resp)
        for t_type, count in res_resp.all():
            if t_type:
                threat_counts[t_type] = threat_counts.get(t_type, 0) + count

        # Convert to response list sorted by count desc
        threats = [
            ThreatStat(type=t_type, count=count)
            for t_type, count in sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)
        ]

        return ThreatDistributionResponse(threats=threats)
    except Exception as exc:
        logger.error("Failed to retrieve threat distribution: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve threat distribution"
        ) from exc


@router.get("/dashboard/recent-events", response_model=RecentEventsResponse)
async def get_recent_events(
    limit: int = Query(default=20, ge=1, le=100),
    user: dict = Depends(require_dashboard_access),
    db: AsyncSession = Depends(get_db)
):
    """
    Return the most recent audit records.
    Guaranteed to only contain security metadata and latency without raw prompt or sensitive API keys.
    """
    try:
        stmt = select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(limit)
        result = await db.execute(stmt)
        records = result.scalars().all()

        events = [
            AuditEventItem(
                request_id=r.request_id,
                timestamp=r.timestamp,
                user=r.user,
                role=r.role,
                model=r.model,
                provider=r.provider or "mock",
                action=r.action,
                risk_score=r.risk_score or 0,
                pii_detected=r.pii_detected or False,
                injection_detected=r.injection_detected or False,
                threat_type=r.threat_type,
                response_status=r.response_status or 200,
                latency_ms=round(float(r.latency_ms or 0.0), 2),
                detected_entities=r.detected_entities or [],
                response_risk_score=r.response_risk_score,
                response_action=r.response_action,
                response_threat_type=r.response_threat_type,
                cache_hit=bool(r.cache_hit)
            )
            for r in records
        ]

        return RecentEventsResponse(events=events)
    except Exception as exc:
        logger.error("Failed to retrieve recent events: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve recent audit events"
        ) from exc


@router.get("/dashboard/models", response_model=ModelAnalyticsResponse)
async def get_model_analytics(
    user: dict = Depends(require_dashboard_access),
    db: AsyncSession = Depends(get_db)
):
    """
    Return model usage statistics, allowed vs blocked ratios, and average latency per model.
    """
    try:
        stmt = select(
            AuditLog.model,
            func.count(AuditLog.id).label("requests"),
            func.count().filter(AuditLog.action != "BLOCK").label("allowed"),
            func.count().filter(AuditLog.action == "BLOCK").label("blocked"),
            func.coalesce(func.avg(AuditLog.latency_ms), 0.0).label("average_latency_ms")
        ).group_by(AuditLog.model).order_by(func.count(AuditLog.id).desc())

        result = await db.execute(stmt)
        models = [
            ModelStat(
                model=row.model or "unknown",
                requests=row.requests or 0,
                allowed=row.allowed or 0,
                blocked=row.blocked or 0,
                average_latency_ms=round(float(row.average_latency_ms or 0.0), 2)
            )
            for row in result.all()
        ]

        return ModelAnalyticsResponse(models=models)
    except Exception as exc:
        logger.error("Failed to retrieve model analytics: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve model analytics"
        ) from exc


@router.get("/dashboard/users", response_model=UserAnalyticsResponse)
async def get_user_analytics(
    user: dict = Depends(require_dashboard_access),
    db: AsyncSession = Depends(get_db)
):
    """
    Return user activity breakdown, roles, request volume, and violation counts.
    """
    try:
        stmt = select(
            AuditLog.user,
            AuditLog.role,
            func.count(AuditLog.id).label("requests"),
            func.count().filter(AuditLog.action == "BLOCK").label("blocked"),
            func.count().filter(AuditLog.pii_detected.is_(True)).label("pii_detections"),
            func.count().filter(AuditLog.injection_detected.is_(True)).label("injection_detections")
        ).group_by(AuditLog.user, AuditLog.role).order_by(func.count(AuditLog.id).desc())

        result = await db.execute(stmt)
        users = [
            UserStat(
                user=row.user or "anonymous",
                role=row.role or "unknown",
                requests=row.requests or 0,
                blocked=row.blocked or 0,
                pii_detections=row.pii_detections or 0,
                injection_detections=row.injection_detections or 0
            )
            for row in result.all()
        ]

        return UserAnalyticsResponse(users=users)
    except Exception as exc:
        logger.error("Failed to retrieve user analytics: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user analytics"
        ) from exc


@router.get("/dashboard/timeline", response_model=TimelineResponse)
async def get_timeline(
    hours: int = Query(default=24, ge=1, le=168),
    user: dict = Depends(require_dashboard_access),
    db: AsyncSession = Depends(get_db)
):
    """
    Return time-series telemetry bucketed by hour.
    """
    try:
        # Group by hourly timestamps
        stmt = select(
            func.to_char(AuditLog.timestamp, "YYYY-MM-DD HH24:00").label("hour_bucket"),
            func.count(AuditLog.id).label("requests"),
            func.count().filter(AuditLog.action == "ALLOW").label("allowed"),
            func.count().filter(AuditLog.action == "BLOCK").label("blocked"),
            func.count().filter(AuditLog.action == "SANITIZE").label("sanitized")
        ).group_by("hour_bucket").order_by("hour_bucket")

        result = await db.execute(stmt)
        timeline = [
            TimelinePoint(
                timestamp=row.hour_bucket,
                requests=row.requests or 0,
                allowed=row.allowed or 0,
                blocked=row.blocked or 0,
                sanitized=row.sanitized or 0
            )
            for row in result.all()
        ]

        return TimelineResponse(timeline=timeline)
    except Exception as exc:
        logger.error("Failed to retrieve timeline analytics: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve timeline analytics"
        ) from exc


@router.get("/dashboard/cache", response_model=CacheStatsResponse)
async def get_cache_stats(
    user: dict = Depends(require_dashboard_access),
    db: AsyncSession = Depends(get_db)
):
    """
    Return semantic cache performance metrics aggregated from PostgreSQL audit records.
    """
    try:
        enabled = is_cache_enabled()
        stmt = select(
            func.count(AuditLog.id).label("total_requests"),
            func.count().filter(AuditLog.cache_hit.is_(True)).label("cache_hits"),
            func.count().filter(AuditLog.action != "BLOCK").label("eligible_requests")
        )
        result = await db.execute(stmt)
        row = result.one()

        total = row.total_requests or 0
        hits = row.cache_hits or 0
        eligible = row.eligible_requests or 0
        misses = max(0, eligible - hits)
        total_cache_requests = hits + misses

        hit_rate = 0.0
        if total_cache_requests > 0:
            hit_rate = round((hits / total_cache_requests) * 100, 1)

        return CacheStatsResponse(
            enabled=enabled,
            hits=hits,
            misses=misses,
            total_cache_requests=total_cache_requests,
            hit_rate=hit_rate
        )
    except Exception as exc:
        logger.error("Failed to retrieve cache analytics: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve cache analytics"
        ) from exc


@router.get("/dashboard/providers", response_model=ProviderAnalyticsResponse)
async def get_provider_analytics(
    user: dict = Depends(require_dashboard_access),
    db: AsyncSession = Depends(get_db)
):
    """
    Return multi-provider operations metrics (request counts, cache hits, blocks, average latency).
    """
    try:
        stmt = select(
            AuditLog.provider,
            func.count(AuditLog.id).label("requests"),
            func.count().filter(AuditLog.cache_hit.is_(True)).label("cache_hits"),
            func.count().filter(AuditLog.action == "BLOCK").label("blocked"),
            func.coalesce(func.avg(AuditLog.latency_ms), 0.0).label("average_latency_ms")
        ).group_by(AuditLog.provider).order_by(func.count(AuditLog.id).desc())

        result = await db.execute(stmt)
        providers = [
            ProviderStat(
                provider=row.provider or "mock",
                requests=row.requests or 0,
                cache_hits=row.cache_hits or 0,
                blocked=row.blocked or 0,
                average_latency_ms=round(float(row.average_latency_ms or 0.0), 2)
            )
            for row in result.all()
        ]

        return ProviderAnalyticsResponse(providers=providers)
    except Exception as exc:
        logger.error("Failed to retrieve provider analytics: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve provider analytics"
        ) from exc


@router.get("/dashboard/observability", response_model=ObservabilityTelemetryResponse)
async def get_observability_metrics(
    user: dict = Depends(require_dashboard_access),
    db: AsyncSession = Depends(get_db)
):
    """
    Return high-level operational and security observability telemetry for SOC operations.
    """
    try:
        stmt = select(
            func.count(AuditLog.id).label("total_requests"),
            func.count().filter(AuditLog.action == "BLOCK").label("blocked_requests"),
            func.count().filter(AuditLog.pii_detected.is_(True)).label("pii_detections"),
            func.count().filter(AuditLog.injection_detected.is_(True)).label("prompt_injections"),
            func.count().filter(AuditLog.response_action == "BLOCK").label("response_blocks"),
            func.count().filter(AuditLog.response_status >= 500).label("provider_errors"),
            func.count().filter(AuditLog.cache_hit.is_(True)).label("cache_hits"),
            func.coalesce(func.avg(AuditLog.latency_ms), 0.0).label("average_latency_ms")
        )
        result = await db.execute(stmt)
        row = result.one()

        total = row.total_requests or 0
        blocked = row.blocked_requests or 0
        pii = row.pii_detections or 0
        injections = row.prompt_injections or 0
        resp_blocks = row.response_blocks or 0
        prov_errors = row.provider_errors or 0
        cache_hits = row.cache_hits or 0
        avg_latency = round(float(row.average_latency_ms or 0.0), 2)

        # Calculate P95 latency
        p95_latency = avg_latency
        try:
            p95_stmt = select(func.percentile_cont(0.95).within_group(AuditLog.latency_ms))
            p95_res = await db.execute(p95_stmt)
            p95_val = p95_res.scalar()
            if p95_val is not None:
                p95_latency = round(float(p95_val), 2)
        except Exception:
            # Fallback to sorted latencies if percentile_cont is unsupported
            lat_stmt = select(AuditLog.latency_ms).order_by(AuditLog.latency_ms.asc())
            lat_res = await db.execute(lat_stmt)
            lat_list = [l for l in lat_res.scalars().all() if l is not None]
            if lat_list:
                idx = int(len(lat_list) * 0.95)
                p95_latency = round(float(lat_list[min(idx, len(lat_list) - 1)]), 2)

        error_rate = round(float((blocked + resp_blocks + prov_errors) / total * 100), 2) if total > 0 else 0.0
        cache_hit_rate = round(float(cache_hits / total * 100), 2) if total > 0 else 0.0
        requests_per_minute = round(float(total), 2)

        return ObservabilityTelemetryResponse(
            requests_per_minute=requests_per_minute,
            error_rate=error_rate,
            blocked_requests=blocked,
            pii_detections=pii,
            prompt_injections=injections,
            response_blocks=resp_blocks,
            provider_errors=prov_errors,
            cache_hit_rate=cache_hit_rate,
            average_latency_ms=avg_latency,
            p95_latency_ms=p95_latency
        )
    except Exception as exc:
        logger.error("Failed to retrieve observability telemetry: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve observability telemetry"
        ) from exc


@router.get("/providers/health", response_model=ProvidersHealthResponse)
async def get_provider_health():
    """
    Report configuration availability for all providers without exposing secrets.
    """
    return get_providers_health()


@router.get("/dashboard/security-posture")
async def get_security_posture(
    user: dict = Depends(require_dashboard_access),
    db: AsyncSession = Depends(get_db)
):
    """
    Return high-level continuous security posture status, scores, alert counts, and policy metadata.
    """
    try:
        from backend.db.models import (
            SecurityCampaignModel,
            SecurityCampaignRunModel,
            SecurityScheduleModel,
            SecurityAlertModel,
            SecurityRegressionModel
        )
        from backend.services.policy_service import get_active_policy

        # 1. Active Policy
        try:
            active_pol = await get_active_policy()
            pol_ver = active_pol.policy_version
        except Exception:
            pol_ver = "1.0.0"

        # 2. Latest Campaign Run Score & Timestamp
        stmt_run = (
            select(SecurityCampaignRunModel)
            .order_by(desc(SecurityCampaignRunModel.started_at))
            .limit(1)
        )
        res_run = await db.execute(stmt_run)
        latest_run = res_run.scalar_one_or_none()

        overall_score = latest_run.security_score if latest_run else 100.0
        baseline_score = latest_run.baseline_score if latest_run and latest_run.baseline_score is not None else overall_score
        score_delta = latest_run.score_delta if latest_run and latest_run.score_delta is not None else 0.0
        last_validation = latest_run.completed_at.isoformat() if latest_run and latest_run.completed_at else None

        # 3. Campaign & Schedule Counts
        stmt_act_camps = select(func.count(SecurityCampaignModel.id)).where(SecurityCampaignModel.status == "ACTIVE")
        active_campaigns = (await db.execute(stmt_act_camps)).scalar() or 0

        stmt_sched = select(func.count(SecurityScheduleModel.id)).where(SecurityScheduleModel.enabled == True)
        scheduled_campaigns = (await db.execute(stmt_sched)).scalar() or 0

        # 4. Open Alerts Breakdown
        stmt_open = select(func.count(SecurityAlertModel.id)).where(SecurityAlertModel.status == "OPEN")
        open_alerts = (await db.execute(stmt_open)).scalar() or 0

        stmt_crit = select(func.count(SecurityAlertModel.id)).where(
            and_(SecurityAlertModel.status == "OPEN", SecurityAlertModel.severity == "CRITICAL")
        )
        critical_alerts = (await db.execute(stmt_crit)).scalar() or 0

        stmt_high = select(func.count(SecurityAlertModel.id)).where(
            and_(SecurityAlertModel.status == "OPEN", SecurityAlertModel.severity == "HIGH")
        )
        high_alerts = (await db.execute(stmt_high)).scalar() or 0

        # 5. Regressions Count
        stmt_regs = select(func.count(SecurityRegressionModel.id))
        regressions = (await db.execute(stmt_regs)).scalar() or 0

        # 6. Posture Classification Status
        if overall_score < 70.0 or critical_alerts > 0:
            posture_status = "CRITICAL"
        elif overall_score < 90.0 or high_alerts > 0:
            posture_status = "DEGRADED"
        else:
            posture_status = "SECURE"

        return {
            "status": posture_status,
            "overall_score": round(overall_score, 2),
            "previous_score": round(baseline_score, 2),
            "score_delta": round(score_delta, 2),
            "active_campaigns": active_campaigns,
            "scheduled_campaigns": scheduled_campaigns,
            "open_alerts": open_alerts,
            "critical_alerts": critical_alerts,
            "high_alerts": high_alerts,
            "regressions": regressions,
            "last_validation": last_validation,
            "policy_version": pol_ver
        }
    except Exception as exc:
        logger.error("Failed to calculate security posture: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to calculate security posture"
        ) from exc

