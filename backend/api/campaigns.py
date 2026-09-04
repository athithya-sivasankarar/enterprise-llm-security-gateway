import logging
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.db.database import get_db
from backend.db.models import SecurityCampaignRunModel
from backend.security.rbac import require_dashboard_access
from backend.campaign.models import (
    CampaignCreateRequest,
    CampaignUpdateRequest,
    CampaignSummary,
    CampaignRunSummary,
    RegressionItem,
    BaselineComparisonResult,
    SetBaselineRequest
)
from backend.services.campaign_service import (
    create_campaign as svc_create_campaign,
    get_campaign as svc_get_campaign,
    list_campaigns as svc_list_campaigns,
    update_campaign as svc_update_campaign,
    pause_campaign as svc_pause_campaign,
    resume_campaign as svc_resume_campaign,
    archive_campaign as svc_archive_campaign,
    set_baseline as svc_set_baseline,
    execute_campaign as svc_execute_campaign,
    get_campaign_history as svc_get_campaign_history,
    get_campaign_regressions as svc_get_campaign_regressions
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/campaigns", tags=["Security Assessment Campaigns"])


@router.post("", response_model=CampaignSummary, status_code=status.HTTP_201_CREATED)
async def create_campaign(
    req: CampaignCreateRequest,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Create a new continuous security assessment campaign.
    Restricted to Admin and Analyst roles (Developer returns HTTP 403).
    """
    username = user_data.get("user", "authenticated-user")
    return await svc_create_campaign(db, req, username)


@router.get("", response_model=List[CampaignSummary])
async def list_campaigns(
    status: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    List all security assessment campaigns.
    """
    return await svc_list_campaigns(db, status)


@router.get("/{campaign_id}", response_model=CampaignSummary)
async def get_campaign(
    campaign_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Get detailed information for a specific security campaign.
    """
    return await svc_get_campaign(db, campaign_id)


@router.put("/{campaign_id}", response_model=CampaignSummary)
async def update_campaign(
    campaign_id: str,
    req: CampaignUpdateRequest,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Update parameters of an existing security campaign.
    """
    username = user_data.get("user", "authenticated-user")
    return await svc_update_campaign(db, campaign_id, req, username)


@router.post("/{campaign_id}/execute")
async def execute_campaign(
    campaign_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Execute a security assessment campaign run against the gateway,
    compare individual results against baseline by test_id, and detect regressions.
    """
    username = user_data.get("user", "authenticated-user")
    run_summary, comparison = await svc_execute_campaign(db, campaign_id, username)
    return {
        "run": run_summary,
        "comparison": comparison
    }


@router.get("/{campaign_id}/runs", response_model=List[CampaignRunSummary])
async def get_campaign_runs(
    campaign_id: str,
    limit: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Retrieve historical execution runs for a campaign.
    """
    return await svc_get_campaign_history(db, campaign_id, limit)


@router.get("/{campaign_id}/runs/{campaign_run_id}", response_model=CampaignRunSummary)
async def get_campaign_run(
    campaign_id: str,
    campaign_run_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Get details of a specific campaign run.
    """
    stmt = (
        select(SecurityCampaignRunModel)
        .where(
            SecurityCampaignRunModel.campaign_id == campaign_id,
            SecurityCampaignRunModel.campaign_run_id == campaign_run_id
        )
    )
    res = await db.execute(stmt)
    row = res.scalar_one_or_none()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Campaign run '{campaign_run_id}' not found."
        )

    return CampaignRunSummary(
        campaign_run_id=row.campaign_run_id,
        campaign_id=row.campaign_id,
        run_id=row.run_id,
        started_at=row.started_at,
        completed_at=row.completed_at,
        status=row.status,
        total_tests=row.total_tests,
        passed_tests=row.passed_tests,
        failed_tests=row.failed_tests,
        error_tests=row.error_tests,
        skipped_tests=row.skipped_tests,
        security_score=row.security_score,
        baseline_score=row.baseline_score,
        score_delta=row.score_delta,
        regression_detected=row.regression_detected,
        created_by=row.created_by,
        policy_version=row.policy_version or "1.0.0"
    )


@router.get("/{campaign_id}/regressions", response_model=List[RegressionItem])
async def get_campaign_regressions(
    campaign_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Retrieve recorded regressions for a campaign.
    """
    return await svc_get_campaign_regressions(db, campaign_id, limit)


@router.post("/{campaign_id}/baseline", response_model=CampaignSummary)
async def set_campaign_baseline(
    campaign_id: str,
    req: SetBaselineRequest,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Explicitly set or update the reference baseline run for a campaign.
    """
    username = user_data.get("user", "authenticated-user")
    return await svc_set_baseline(db, campaign_id, req.run_id, username)


@router.post("/{campaign_id}/pause", response_model=CampaignSummary)
async def pause_campaign(
    campaign_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Pause an active campaign.
    """
    username = user_data.get("user", "authenticated-user")
    return await svc_pause_campaign(db, campaign_id, username)


@router.post("/{campaign_id}/resume", response_model=CampaignSummary)
async def resume_campaign(
    campaign_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Resume a paused campaign.
    """
    username = user_data.get("user", "authenticated-user")
    return await svc_resume_campaign(db, campaign_id, username)


@router.post("/{campaign_id}/archive", response_model=CampaignSummary)
async def archive_campaign(
    campaign_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Archive a campaign.
    """
    username = user_data.get("user", "authenticated-user")
    return await svc_archive_campaign(db, campaign_id, username)
