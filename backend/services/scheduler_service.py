import uuid
import logging
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func, delete, and_


from backend.db.models import SecurityScheduleModel, SecurityCampaignModel
from backend.campaign.models import CampaignStatus
from backend.scheduler.models import (
    ScheduleType,
    ScheduleCreateRequest,
    ScheduleUpdateRequest,
    ScheduleSummary,
    SchedulerStatus,
    NextRunEstimate
)
from backend.scheduler.parser import (
    validate_interval_minutes,
    validate_cron_expression,
    calculate_next_run_at,
    MINIMUM_INTERVAL_MINUTES
)
from backend.scheduler.worker import get_worker_status
from backend.services.campaign_service import execute_campaign
from backend.alerts.engine import evaluate_campaign_alerts
from backend.observability.metrics import record_scheduled_campaigns_metric
from backend.observability.logging import log_security_event

logger = logging.getLogger(__name__)


async def create_schedule(
    db: AsyncSession,
    campaign_id: str,
    req: ScheduleCreateRequest,
    user: str
) -> ScheduleSummary:
    """
    Create a recurring schedule for a security assessment campaign.
    Enforces minimum 60-minute interval policy on both INTERVAL and CRON.
    """
    # 1. Verify Campaign exists and is ACTIVE
    stmt_camp = select(SecurityCampaignModel).where(SecurityCampaignModel.campaign_id == campaign_id)
    res_camp = await db.execute(stmt_camp)
    campaign = res_camp.scalar_one_or_none()

    if not campaign:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security campaign '{campaign_id}' not found."
        )

    if campaign.status == CampaignStatus.ARCHIVED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot schedule archived campaign '{campaign_id}'."
        )

    # 2. Check if a schedule already exists
    stmt_sched = select(SecurityScheduleModel).where(SecurityScheduleModel.campaign_id == campaign_id)
    res_sched = await db.execute(stmt_sched)
    existing = res_sched.scalar_one_or_none()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A schedule already exists for campaign '{campaign_id}'. Use PUT to update it."
        )

    # 3. Validate Schedule Configuration & 60-minute Safety Policy
    st_type = req.schedule_type.upper() if req.schedule_type else ScheduleType.INTERVAL.value
    if st_type not in (ScheduleType.INTERVAL.value, ScheduleType.CRON.value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid schedule_type '{req.schedule_type}'. Must be 'INTERVAL' or 'CRON'."
        )

    if st_type == ScheduleType.CRON.value:
        valid, err_msg = validate_cron_expression(req.cron_expression)
        if not valid:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_msg)
    else:
        valid, err_msg = validate_interval_minutes(req.interval_minutes)
        if not valid:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_msg)

    # 4. Calculate next execution timestamp
    now = datetime.now(timezone.utc)
    next_run = calculate_next_run_at(
        schedule_type=st_type,
        interval_minutes=req.interval_minutes,
        cron_expression=req.cron_expression,
        from_time=now
    ) if req.enabled else None

    schedule_id = f"sched-{uuid.uuid4().hex[:12]}"
    model = SecurityScheduleModel(
        schedule_id=schedule_id,
        campaign_id=campaign_id,
        enabled=bool(req.enabled),
        schedule_type=st_type,
        cron_expression=req.cron_expression,
        interval_minutes=req.interval_minutes if st_type == ScheduleType.INTERVAL.value else None,
        timezone=req.timezone or "UTC",
        next_run_at=next_run,
        created_by=user,
        created_at=now,
        updated_at=now
    )

    db.add(model)
    await db.commit()
    await db.refresh(model)

    await _sync_schedule_gauges(db)

    log_security_event(
        event_type="CAMPAIGN_SCHEDULED",
        request_id=f"sched-create-{schedule_id}",
        action="ALLOW",
        response_status=201,
        user=user,
        role="security-lead",
        threat_type=st_type
    )

    return _to_schedule_summary(model)


async def get_schedule(db: AsyncSession, campaign_id: str) -> ScheduleSummary:
    """
    Get the schedule for a campaign.
    """
    stmt = select(SecurityScheduleModel).where(SecurityScheduleModel.campaign_id == campaign_id)
    res = await db.execute(stmt)
    row = res.scalar_one_or_none()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No schedule found for campaign '{campaign_id}'."
        )
    return _to_schedule_summary(row)


async def list_schedules(db: AsyncSession) -> List[ScheduleSummary]:
    """
    List all configured campaign schedules.
    """
    stmt = select(SecurityScheduleModel).order_by(desc(SecurityScheduleModel.updated_at))
    res = await db.execute(stmt)
    rows = res.scalars().all()
    return [_to_schedule_summary(r) for r in rows]


async def update_schedule(
    db: AsyncSession,
    campaign_id: str,
    req: ScheduleUpdateRequest,
    user: str
) -> ScheduleSummary:
    """
    Update configuration of an existing campaign schedule.
    """
    stmt = select(SecurityScheduleModel).where(SecurityScheduleModel.campaign_id == campaign_id)
    res = await db.execute(stmt)
    row = res.scalar_one_or_none()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No schedule found for campaign '{campaign_id}'."
        )

    st_type = req.schedule_type.upper() if req.schedule_type else row.schedule_type
    if req.schedule_type is not None:
        if st_type not in (ScheduleType.INTERVAL.value, ScheduleType.CRON.value):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid schedule_type '{req.schedule_type}'. Must be 'INTERVAL' or 'CRON'."
            )
        row.schedule_type = st_type

    if req.cron_expression is not None:
        valid, err_msg = validate_cron_expression(req.cron_expression)
        if not valid:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_msg)
        row.cron_expression = req.cron_expression

    if req.interval_minutes is not None:
        valid, err_msg = validate_interval_minutes(req.interval_minutes)
        if not valid:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_msg)
        row.interval_minutes = req.interval_minutes

    if req.timezone is not None:
        row.timezone = req.timezone

    if req.enabled is not None:
        row.enabled = req.enabled

    now = datetime.now(timezone.utc)
    if row.enabled:
        row.next_run_at = calculate_next_run_at(
            row.schedule_type,
            row.interval_minutes,
            row.cron_expression,
            now
        )
    else:
        row.next_run_at = None

    row.updated_at = now
    await db.commit()
    await db.refresh(row)
    await _sync_schedule_gauges(db)

    return _to_schedule_summary(row)


async def enable_schedule(db: AsyncSession, campaign_id: str, user: str) -> ScheduleSummary:
    """
    Enable a disabled campaign schedule.
    """
    return await update_schedule(db, campaign_id, ScheduleUpdateRequest(enabled=True), user)


async def disable_schedule(db: AsyncSession, campaign_id: str, user: str) -> ScheduleSummary:
    """
    Disable an active campaign schedule.
    """
    return await update_schedule(db, campaign_id, ScheduleUpdateRequest(enabled=False), user)


async def delete_schedule(db: AsyncSession, campaign_id: str, user: str) -> dict:
    """
    Delete a schedule for a campaign.
    """
    stmt = select(SecurityScheduleModel).where(SecurityScheduleModel.campaign_id == campaign_id)
    res = await db.execute(stmt)
    row = res.scalar_one_or_none()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No schedule found for campaign '{campaign_id}'."
        )

    await db.delete(row)
    await db.commit()
    await _sync_schedule_gauges(db)

    return {"status": "deleted", "campaign_id": campaign_id, "schedule_id": row.schedule_id}


async def get_scheduler_status(db: AsyncSession) -> SchedulerStatus:
    """
    Retrieve overarching scheduler operational status.
    """
    worker_info = get_worker_status()

    stmt_total = select(func.count(SecurityScheduleModel.id))
    res_total = await db.execute(stmt_total)
    total_schedules = res_total.scalar() or 0

    stmt_enabled = select(func.count(SecurityScheduleModel.id)).where(SecurityScheduleModel.enabled == True)
    res_enabled = await db.execute(stmt_enabled)
    enabled_schedules = res_enabled.scalar() or 0

    return SchedulerStatus(
        scheduler_enabled=worker_info["scheduler_enabled"],
        worker_running=worker_info["worker_running"],
        poll_interval_seconds=worker_info["poll_interval_seconds"],
        total_schedules=total_schedules,
        enabled_schedules=enabled_schedules,
        last_poll_at=worker_info["last_poll_at"]
    )


async def get_next_runs(db: AsyncSession, limit: int = 10) -> List[NextRunEstimate]:
    """
    List upcoming scheduled campaign runs.
    """
    now = datetime.now(timezone.utc)
    stmt = (
        select(SecurityScheduleModel)
        .where(
            and_(
                SecurityScheduleModel.enabled == True,
                SecurityScheduleModel.next_run_at != None
            )
        )
        .order_by(SecurityScheduleModel.next_run_at)
        .limit(limit)
    )
    res = await db.execute(stmt)
    rows = res.scalars().all()

    estimates = []
    for r in rows:
        seconds_left = max(0, int((r.next_run_at - now).total_seconds())) if r.next_run_at else None
        estimates.append(
            NextRunEstimate(
                schedule_id=r.schedule_id,
                campaign_id=r.campaign_id,
                next_run_at=r.next_run_at,
                seconds_until_run=seconds_left
            )
        )
    return estimates


async def trigger_scheduled_campaign(
    db: AsyncSession,
    campaign_id: str,
    user: str,
    custom_client=None
) -> Tuple[Any, Any]:
    """
    Manually trigger immediate execution of a scheduled campaign.
    Reuses execute_campaign() with the unified distributed Redis lock.
    """
    # Verify schedule exists
    stmt = select(SecurityScheduleModel).where(SecurityScheduleModel.campaign_id == campaign_id)
    res = await db.execute(stmt)
    sched = res.scalar_one_or_none()

    # Execute campaign
    run_summary, comparison = await execute_campaign(
        db=db,
        campaign_id=campaign_id,
        user=f"manual-trigger:{user}",
        custom_client=custom_client
    )

    # Evaluate alerts
    await evaluate_campaign_alerts(
        db=db,
        campaign_id=campaign_id,
        campaign_run_id=run_summary.campaign_run_id,
        run_summary=run_summary,
        comparison=comparison,
        policy_version=run_summary.policy_version
    )

    # Update schedule last_run if schedule exists
    if sched:
        now = datetime.now(timezone.utc)
        sched.last_run_at = now
        sched.last_run_status = run_summary.status
        sched.last_error = None
        if sched.enabled:
            sched.next_run_at = calculate_next_run_at(
                sched.schedule_type,
                sched.interval_minutes,
                sched.cron_expression,
                now
            )
        sched.updated_at = now
        await db.commit()

    return run_summary, comparison


async def _sync_schedule_gauges(db: AsyncSession):
    try:
        stmt_en = select(func.count(SecurityScheduleModel.id)).where(SecurityScheduleModel.enabled == True)
        res_en = await db.execute(stmt_en)
        en_count = res_en.scalar() or 0

        stmt_dis = select(func.count(SecurityScheduleModel.id)).where(SecurityScheduleModel.enabled == False)
        res_dis = await db.execute(stmt_dis)
        dis_count = res_dis.scalar() or 0

        record_scheduled_campaigns_metric(en_count, dis_count)
    except Exception as e:
        logger.debug(f"Failed to sync schedule gauges: {e}")


def _to_schedule_summary(row: SecurityScheduleModel) -> ScheduleSummary:
    return ScheduleSummary(
        schedule_id=row.schedule_id,
        campaign_id=row.campaign_id,
        enabled=row.enabled,
        schedule_type=row.schedule_type,
        cron_expression=row.cron_expression,
        interval_minutes=row.interval_minutes,
        timezone=row.timezone or "UTC",
        next_run_at=row.next_run_at,
        last_run_at=row.last_run_at,
        last_run_status=row.last_run_status,
        last_error=row.last_error,
        created_by=row.created_by,
        created_at=row.created_at,
        updated_at=row.updated_at
    )
