import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func, and_

from backend.db.models import SecurityAlertModel
from backend.alerts.models import (
    AlertStatus,
    AlertSeverity,
    SecurityAlert,
    AlertSummary
)
from backend.observability.metrics import set_security_alerts_open_metric
from backend.observability.logging import log_security_event

logger = logging.getLogger(__name__)


async def list_alerts(
    db: AsyncSession,
    status_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    limit: int = 50
) -> List[SecurityAlert]:
    """
    List security alerts with optional status and severity filtering.
    """
    query = select(SecurityAlertModel).order_by(desc(SecurityAlertModel.created_at))
    if status_filter:
        query = query.where(SecurityAlertModel.status == status_filter.upper())
    if severity_filter:
        query = query.where(SecurityAlertModel.severity == severity_filter.upper())

    query = query.limit(limit)
    res = await db.execute(query)
    rows = res.scalars().all()
    return [_to_security_alert(r) for r in rows]


async def get_alert(db: AsyncSession, alert_id: str) -> SecurityAlert:
    """
    Retrieve specific alert by alert_id.
    """
    stmt = select(SecurityAlertModel).where(SecurityAlertModel.alert_id == alert_id)
    res = await db.execute(stmt)
    row = res.scalar_one_or_none()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found."
        )
    return _to_security_alert(row)


async def get_open_alerts(db: AsyncSession, limit: int = 50) -> List[SecurityAlert]:
    """
    Retrieve active open security alerts requiring SOC triage.
    """
    return await list_alerts(db, status_filter=AlertStatus.OPEN.value, limit=limit)


async def acknowledge_alert(db: AsyncSession, alert_id: str, user: str) -> SecurityAlert:
    """
    Acknowledge an open security alert.
    """
    stmt = select(SecurityAlertModel).where(SecurityAlertModel.alert_id == alert_id)
    res = await db.execute(stmt)
    row = res.scalar_one_or_none()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found."
        )

    now = datetime.now(timezone.utc)
    row.status = AlertStatus.ACKNOWLEDGED.value
    row.acknowledged_at = now
    row.acknowledged_by = user
    await db.commit()
    await db.refresh(row)

    await _sync_open_alert_gauges(db)

    log_security_event(
        event_type="SECURITY_ALERT_ACKNOWLEDGED",
        request_id=f"alert-ack-{alert_id}",
        action="ALLOW",
        response_status=200,
        user=user,
        role="security-lead",
        threat_type=row.alert_type
    )

    return _to_security_alert(row)


async def resolve_alert(db: AsyncSession, alert_id: str, user: str) -> SecurityAlert:
    """
    Mark a security alert as resolved.
    """
    stmt = select(SecurityAlertModel).where(SecurityAlertModel.alert_id == alert_id)
    res = await db.execute(stmt)
    row = res.scalar_one_or_none()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found."
        )

    now = datetime.now(timezone.utc)
    row.status = AlertStatus.RESOLVED.value
    row.resolved_at = now
    row.resolved_by = user
    await db.commit()
    await db.refresh(row)

    await _sync_open_alert_gauges(db)

    log_security_event(
        event_type="SECURITY_ALERT_RESOLVED",
        request_id=f"alert-res-{alert_id}",
        action="ALLOW",
        response_status=200,
        user=user,
        role="security-lead",
        threat_type=row.alert_type
    )

    return _to_security_alert(row)


async def get_alert_summary(db: AsyncSession) -> AlertSummary:
    """
    Calculate summary metrics for security alerts and sync gauges.
    """
    stmt_total = select(func.count(SecurityAlertModel.id))
    total = (await db.execute(stmt_total)).scalar() or 0

    stmt_open = select(func.count(SecurityAlertModel.id)).where(SecurityAlertModel.status == AlertStatus.OPEN.value)
    open_count = (await db.execute(stmt_open)).scalar() or 0

    stmt_ack = select(func.count(SecurityAlertModel.id)).where(SecurityAlertModel.status == AlertStatus.ACKNOWLEDGED.value)
    ack_count = (await db.execute(stmt_ack)).scalar() or 0

    stmt_res = select(func.count(SecurityAlertModel.id)).where(SecurityAlertModel.status == AlertStatus.RESOLVED.value)
    res_count = (await db.execute(stmt_res)).scalar() or 0

    # Severity counts for open alerts
    stmt_crit = select(func.count(SecurityAlertModel.id)).where(
        and_(SecurityAlertModel.status == AlertStatus.OPEN.value, SecurityAlertModel.severity == AlertSeverity.CRITICAL.value)
    )
    crit_count = (await db.execute(stmt_crit)).scalar() or 0

    stmt_high = select(func.count(SecurityAlertModel.id)).where(
        and_(SecurityAlertModel.status == AlertStatus.OPEN.value, SecurityAlertModel.severity == AlertSeverity.HIGH.value)
    )
    high_count = (await db.execute(stmt_high)).scalar() or 0

    stmt_med = select(func.count(SecurityAlertModel.id)).where(
        and_(SecurityAlertModel.status == AlertStatus.OPEN.value, SecurityAlertModel.severity == AlertSeverity.MEDIUM.value)
    )
    med_count = (await db.execute(stmt_med)).scalar() or 0

    stmt_low = select(func.count(SecurityAlertModel.id)).where(
        and_(SecurityAlertModel.status == AlertStatus.OPEN.value, SecurityAlertModel.severity == AlertSeverity.LOW.value)
    )
    low_count = (await db.execute(stmt_low)).scalar() or 0

    # Sync Prometheus gauges
    set_security_alerts_open_metric("CRITICAL", crit_count)
    set_security_alerts_open_metric("HIGH", high_count)
    set_security_alerts_open_metric("MEDIUM", med_count)
    set_security_alerts_open_metric("LOW", low_count)

    return AlertSummary(
        total_alerts=total,
        open_alerts=open_count,
        acknowledged_alerts=ack_count,
        resolved_alerts=res_count,
        critical_count=crit_count,
        high_count=high_count,
        medium_count=med_count,
        low_count=low_count
    )


async def _sync_open_alert_gauges(db: AsyncSession):
    try:
        await get_alert_summary(db)
    except Exception as e:
        logger.debug(f"Failed to sync alert gauges: {e}")


def _to_security_alert(row: SecurityAlertModel) -> SecurityAlert:
    return SecurityAlert(
        alert_id=row.alert_id,
        campaign_id=row.campaign_id,
        campaign_run_id=row.campaign_run_id,
        alert_type=row.alert_type,
        severity=row.severity,
        status=row.status,
        title=row.title,
        description=row.description,
        score=row.score,
        baseline_score=row.baseline_score,
        score_delta=row.score_delta,
        regression_count=row.regression_count,
        policy_version=row.policy_version or "1.0.0",
        created_at=row.created_at,
        acknowledged_at=row.acknowledged_at,
        acknowledged_by=row.acknowledged_by,
        resolved_at=row.resolved_at,
        resolved_by=row.resolved_by
    )
