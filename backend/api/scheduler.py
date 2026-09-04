import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.database import get_db
from backend.security.rbac import require_dashboard_access
from backend.scheduler.models import (
    ScheduleCreateRequest,
    ScheduleUpdateRequest,
    ScheduleSummary,
    SchedulerStatus,
    NextRunEstimate
)
from backend.services.scheduler_service import (
    create_schedule as svc_create_schedule,
    get_schedule as svc_get_schedule,
    list_schedules as svc_list_schedules,
    update_schedule as svc_update_schedule,
    enable_schedule as svc_enable_schedule,
    disable_schedule as svc_disable_schedule,
    delete_schedule as svc_delete_schedule,
    get_scheduler_status as svc_get_scheduler_status,
    get_next_runs as svc_get_next_runs,
    trigger_scheduled_campaign as svc_trigger_scheduled_campaign
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scheduler", tags=["Security Assessment Scheduler"])


@router.post("/campaigns/{campaign_id}", response_model=ScheduleSummary, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    campaign_id: str,
    req: ScheduleCreateRequest,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Create a recurring assessment schedule for a campaign.
    Restricted to Admin and Analyst roles (Developer returns HTTP 403).
    """
    username = user_data.get("user", "authenticated-user")
    return await svc_create_schedule(db, campaign_id, req, username)


@router.get("/campaigns", response_model=List[ScheduleSummary])
async def list_schedules(
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    List all configured campaign schedules.
    """
    return await svc_list_schedules(db)


@router.get("/campaigns/{campaign_id}", response_model=ScheduleSummary)
async def get_schedule(
    campaign_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Get the schedule for a specific campaign.
    """
    return await svc_get_schedule(db, campaign_id)


@router.put("/campaigns/{campaign_id}", response_model=ScheduleSummary)
async def update_schedule(
    campaign_id: str,
    req: ScheduleUpdateRequest,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Update configuration of an existing campaign schedule.
    """
    username = user_data.get("user", "authenticated-user")
    return await svc_update_schedule(db, campaign_id, req, username)


@router.post("/campaigns/{campaign_id}/enable", response_model=ScheduleSummary)
async def enable_schedule(
    campaign_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Enable a disabled campaign schedule.
    """
    username = user_data.get("user", "authenticated-user")
    return await svc_enable_schedule(db, campaign_id, username)


@router.post("/campaigns/{campaign_id}/disable", response_model=ScheduleSummary)
async def disable_schedule(
    campaign_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Disable an active campaign schedule.
    """
    username = user_data.get("user", "authenticated-user")
    return await svc_disable_schedule(db, campaign_id, username)


@router.delete("/campaigns/{campaign_id}")
async def delete_schedule(
    campaign_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Delete a schedule for a campaign.
    """
    username = user_data.get("user", "authenticated-user")
    return await svc_delete_schedule(db, campaign_id, username)


@router.get("/status", response_model=SchedulerStatus)
async def get_scheduler_status(
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Get overarching status and statistics of the campaign scheduler.
    """
    return await svc_get_scheduler_status(db)


@router.get("/next-runs", response_model=List[NextRunEstimate])
async def get_next_runs(
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    List upcoming scheduled campaign execution times.
    """
    return await svc_get_next_runs(db)


@router.post("/campaigns/{campaign_id}/trigger")
async def trigger_scheduled_campaign(
    campaign_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Manually trigger immediate execution of a scheduled campaign.
    Enforces unified distributed Redis locking.
    """
    username = user_data.get("user", "authenticated-user")
    run_summary, comparison = await svc_trigger_scheduled_campaign(db, campaign_id, username)
    return {
        "run": run_summary,
        "comparison": comparison
    }
