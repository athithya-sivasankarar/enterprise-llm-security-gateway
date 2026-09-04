import logging
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from backend.db.database import AsyncSessionLocal
from backend.db.models import SecurityScheduleModel, SecurityCampaignModel
from backend.campaign.models import CampaignStatus
from backend.scheduler.parser import calculate_next_run_at, validate_cron_expression, validate_interval_minutes
from backend.services.campaign_service import execute_campaign
from backend.alerts.engine import evaluate_campaign_alerts, record_execution_error_alert, record_scheduler_error_alert
from backend.observability.metrics import (
    record_scheduled_campaign_run_metric,
    record_scheduler_error_metric
)
from backend.observability.logging import log_security_event

logger = logging.getLogger(__name__)


async def get_due_schedules(db: AsyncSession, as_of: Optional[datetime] = None) -> List[SecurityScheduleModel]:
    """
    Query all enabled schedules where next_run_at is due.
    """
    check_time = as_of or datetime.now(timezone.utc)
    stmt = (
        select(SecurityScheduleModel)
        .where(
            and_(
                SecurityScheduleModel.enabled == True,
                SecurityScheduleModel.next_run_at <= check_time
            )
        )
    )
    res = await db.execute(stmt)
    return res.scalars().all()


async def execute_scheduled_campaign(
    schedule_id: str,
    custom_client=None
) -> Tuple[bool, Optional[str]]:
    """
    Execute an automated scheduled campaign:
    1. Validates campaign status (must be ACTIVE, not PAUSED or ARCHIVED).
    2. Executes campaign through existing campaign service (which acquires distributed Redis lock).
    3. Triggers alert engine on regressions / score degradation.
    4. Calculates and updates next_run_at.
    5. Records metrics and SIEM security events.
    """
    async with AsyncSessionLocal() as db:
        stmt = select(SecurityScheduleModel).where(SecurityScheduleModel.schedule_id == schedule_id)
        res = await db.execute(stmt)
        schedule = res.scalar_one_or_none()

        if not schedule:
            logger.error(f"Schedule '{schedule_id}' not found.")
            return False, "Schedule not found"

        if not schedule.enabled:
            logger.info(f"Schedule '{schedule_id}' is disabled. Skipping execution.")
            return False, "Schedule disabled"

        # Check Campaign
        stmt_camp = select(SecurityCampaignModel).where(SecurityCampaignModel.campaign_id == schedule.campaign_id)
        res_camp = await db.execute(stmt_camp)
        campaign = res_camp.scalar_one_or_none()

        if not campaign:
            err = f"Campaign '{schedule.campaign_id}' not found for schedule '{schedule_id}'."
            logger.error(err)
            schedule.last_error = err
            schedule.last_run_status = "FAILED"
            await db.commit()
            await record_scheduler_error_alert(db, schedule.campaign_id, err)
            record_scheduler_error_metric(schedule.campaign_id, "CAMPAIGN_NOT_FOUND")
            return False, err

        if campaign.status != CampaignStatus.ACTIVE.value:
            msg = f"Campaign '{campaign.campaign_id}' is {campaign.status}. Skipping scheduled run."
            logger.info(msg)
            # Advance next_run_at without executing
            now = datetime.now(timezone.utc)
            schedule.next_run_at = calculate_next_run_at(
                schedule.schedule_type,
                schedule.interval_minutes,
                schedule.cron_expression,
                now
            )
            schedule.updated_at = now
            await db.commit()
            return False, msg

        # Pre-execution validation check
        if schedule.schedule_type == "CRON":
            valid, err_msg = validate_cron_expression(schedule.cron_expression)
            if not valid:
                logger.error(f"Cron validation failed before execution for '{schedule_id}': {err_msg}")
                schedule.last_error = err_msg
                schedule.last_run_status = "FAILED"
                await db.commit()
                record_scheduler_error_metric(schedule.campaign_id, "INVALID_CRON")
                return False, err_msg
        else:
            valid, err_msg = validate_interval_minutes(schedule.interval_minutes)
            if not valid:
                logger.error(f"Interval validation failed before execution for '{schedule_id}': {err_msg}")
                schedule.last_error = err_msg
                schedule.last_run_status = "FAILED"
                await db.commit()
                record_scheduler_error_metric(schedule.campaign_id, "INVALID_INTERVAL")
                return False, err_msg

        logger.info(f"Executing scheduled assessment campaign '{campaign.campaign_id}' (Schedule: {schedule_id})...")

        now = datetime.now(timezone.utc)
        try:
            run_summary, comparison = await execute_campaign(
                db=db,
                campaign_id=campaign.campaign_id,
                user=f"scheduler:{schedule_id}",
                custom_client=custom_client
            )

            # Evaluate alerts
            await evaluate_campaign_alerts(
                db=db,
                campaign_id=campaign.campaign_id,
                campaign_run_id=run_summary.campaign_run_id,
                run_summary=run_summary,
                comparison=comparison,
                policy_version=run_summary.policy_version
            )

            # Update schedule state
            schedule.last_run_at = now
            schedule.last_run_status = run_summary.status
            schedule.last_error = None
            schedule.next_run_at = calculate_next_run_at(
                schedule.schedule_type,
                schedule.interval_minutes,
                schedule.cron_expression,
                now
            )
            schedule.updated_at = now
            await db.commit()

            # Record metrics & SIEM
            record_scheduled_campaign_run_metric(campaign.campaign_id, run_summary.status)
            log_security_event(
                event_type="CAMPAIGN_AUTO_EXECUTED",
                request_id=f"sched-exec-{schedule_id}",
                action="ALLOW",
                response_status=200,
                user=f"scheduler:{schedule_id}",
                role="automated-scheduler",
                threat_type="SCHEDULED_RUN",
                risk_score=0
            )

            logger.info(
                f"Successfully completed scheduled run for campaign '{campaign.campaign_id}'. "
                f"Status: {run_summary.status}, Score: {run_summary.security_score}%, Next: {schedule.next_run_at}"
            )
            return True, None

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Scheduled execution failed for campaign '{campaign.campaign_id}': {error_msg}")
            
            schedule.last_run_at = now
            schedule.last_run_status = "FAILED"
            schedule.last_error = error_msg
            schedule.next_run_at = calculate_next_run_at(
                schedule.schedule_type,
                schedule.interval_minutes,
                schedule.cron_expression,
                now
            )
            schedule.updated_at = now
            await db.commit()

            await record_execution_error_alert(db, campaign.campaign_id, error_msg)
            record_scheduler_error_metric(campaign.campaign_id, "EXECUTION_ERROR")

            log_security_event(
                event_type="CAMPAIGN_EXECUTION_ERROR",
                request_id=f"sched-err-{schedule_id}",
                action="BLOCK",
                response_status=500,
                user=f"scheduler:{schedule_id}",
                role="automated-scheduler",
                threat_type="SCHEDULER_EXECUTION_ERROR",
                risk_score=80
            )
            return False, error_msg
