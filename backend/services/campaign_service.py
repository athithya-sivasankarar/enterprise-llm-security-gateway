import uuid
import logging
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, update

from backend.db.models import (
    SecurityCampaignModel,
    SecurityCampaignRunModel,
    SecurityRegressionModel,
    SecurityTestRunModel,
    SecurityTestResultModel
)
from backend.campaign.models import (
    CampaignStatus,
    CampaignCreateRequest,
    CampaignUpdateRequest,
    CampaignSummary,
    CampaignRunSummary,
    RegressionItem,
    BaselineComparisonResult
)
from backend.campaign.comparator import compare_runs_with_baseline
from backend.redteam.runner import run_security_validation_suite
from backend.services.policy_service import get_active_policy
from backend.services.scheduler_lock import acquire_campaign_lock, release_campaign_lock
from backend.observability.metrics import (
    record_campaign_run_metric,
    record_regression_detected_metric,
    record_campaign_score_delta_metric,
    record_scheduler_error_metric,
    set_campaign_security_score_metrics
)
from backend.observability.logging import log_security_event

logger = logging.getLogger(__name__)



async def create_campaign(
    db: AsyncSession,
    req: CampaignCreateRequest,
    user: str
) -> CampaignSummary:
    """
    Create a new security assessment campaign.
    """
    campaign_id = f"camp-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)

    # Resolve active policy version
    try:
        active_policy = await get_active_policy()
        pol_ver = active_policy.policy_version
    except Exception:
        pol_ver = req.policy_version or "1.0.0"

    model = SecurityCampaignModel(
        campaign_id=campaign_id,
        name=req.name,
        description=req.description,
        status=CampaignStatus.ACTIVE.value,
        created_by=user,
        created_at=now,
        updated_at=now,
        schedule_enabled=bool(req.schedule_enabled),
        schedule_interval=req.schedule_interval or "daily",
        category_filter=req.category_filter or [],
        policy_version=pol_ver,
        baseline_run_id=req.baseline_run_id
    )

    db.add(model)
    await db.commit()
    await db.refresh(model)

    log_security_event(
        event_type="CAMPAIGN_CREATED",
        request_id=f"camp-create-{campaign_id}",
        action="ALLOW",
        response_status=201,
        user=user,
        role="security-lead"
    )

    return _to_campaign_summary(model)


async def get_campaign(db: AsyncSession, campaign_id: str) -> CampaignSummary:
    """
    Retrieve campaign by campaign_id.
    """
    stmt = select(SecurityCampaignModel).where(SecurityCampaignModel.campaign_id == campaign_id)
    res = await db.execute(stmt)
    row = res.scalar_one_or_none()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security campaign '{campaign_id}' not found."
        )

    # Fetch latest run info for delta metrics
    latest_run = await _get_latest_campaign_run(db, campaign_id)
    return _to_campaign_summary(row, latest_run)


async def list_campaigns(
    db: AsyncSession,
    status_filter: Optional[str] = None
) -> List[CampaignSummary]:
    """
    List all campaigns with optional status filtering.
    """
    query = select(SecurityCampaignModel).order_by(desc(SecurityCampaignModel.updated_at))
    if status_filter:
        query = query.where(SecurityCampaignModel.status == status_filter.upper())

    res = await db.execute(query)
    rows = res.scalars().all()

    summaries = []
    for r in rows:
        latest_run = await _get_latest_campaign_run(db, r.campaign_id)
        summaries.append(_to_campaign_summary(r, latest_run))
    return summaries


async def update_campaign(
    db: AsyncSession,
    campaign_id: str,
    req: CampaignUpdateRequest,
    user: str
) -> CampaignSummary:
    """
    Update campaign parameters.
    """
    stmt = select(SecurityCampaignModel).where(SecurityCampaignModel.campaign_id == campaign_id)
    res = await db.execute(stmt)
    row = res.scalar_one_or_none()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security campaign '{campaign_id}' not found."
        )

    if req.name is not None:
        row.name = req.name
    if req.description is not None:
        row.description = req.description
    if req.category_filter is not None:
        row.category_filter = req.category_filter
    if req.schedule_enabled is not None:
        row.schedule_enabled = req.schedule_enabled
    if req.schedule_interval is not None:
        row.schedule_interval = req.schedule_interval
    if req.status is not None:
        row.status = req.status.upper()
    if req.baseline_run_id is not None:
        row.baseline_run_id = req.baseline_run_id

    row.updated_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(row)

    latest_run = await _get_latest_campaign_run(db, campaign_id)
    return _to_campaign_summary(row, latest_run)


async def pause_campaign(db: AsyncSession, campaign_id: str, user: str) -> CampaignSummary:
    return await update_campaign(db, campaign_id, CampaignUpdateRequest(status=CampaignStatus.PAUSED.value), user)


async def resume_campaign(db: AsyncSession, campaign_id: str, user: str) -> CampaignSummary:
    return await update_campaign(db, campaign_id, CampaignUpdateRequest(status=CampaignStatus.ACTIVE.value), user)


async def archive_campaign(db: AsyncSession, campaign_id: str, user: str) -> CampaignSummary:
    return await update_campaign(db, campaign_id, CampaignUpdateRequest(status=CampaignStatus.ARCHIVED.value), user)


async def set_baseline(
    db: AsyncSession,
    campaign_id: str,
    run_id: str,
    user: str
) -> CampaignSummary:
    """
    Explicitly set or update the reference baseline run for a campaign.
    """
    # Verify run exists
    stmt_run = select(SecurityTestRunModel).where(SecurityTestRunModel.run_id == run_id)
    res_run = await db.execute(stmt_run)
    run_row = res_run.scalar_one_or_none()

    if not run_row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Test run '{run_id}' not found to set as baseline."
        )

    stmt_camp = select(SecurityCampaignModel).where(SecurityCampaignModel.campaign_id == campaign_id)
    res_camp = await db.execute(stmt_camp)
    camp_row = res_camp.scalar_one_or_none()

    if not camp_row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security campaign '{campaign_id}' not found."
        )

    camp_row.baseline_run_id = run_id
    camp_row.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(camp_row)

    log_security_event(
        event_type="CAMPAIGN_BASELINE_UPDATED",
        request_id=f"camp-base-{campaign_id}",
        action="ALLOW",
        response_status=200,
        user=user,
        role="security-lead"
    )

    latest_run = await _get_latest_campaign_run(db, campaign_id)
    return _to_campaign_summary(camp_row, latest_run)


async def execute_campaign(
    db: AsyncSession,
    campaign_id: str,
    user: str,
    custom_client=None
) -> Tuple[CampaignRunSummary, BaselineComparisonResult]:
    """
    Execute a security assessment campaign run:
    1. Reuses backend/redteam/runner.py with campaign category filter
    2. Compares individual persisted test results against baseline by test_id
    3. Persists SecurityCampaignRunModel and SecurityRegressionModel records
    4. Emits Prometheus metrics and SIEM security events
    """
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
            detail=f"Cannot execute archived campaign '{campaign_id}'."
        )

    # Acquire distributed Redis execution lock to prevent overlapping runs
    lock_acquired = await acquire_campaign_lock(campaign_id, ttl_seconds=300)
    if not lock_acquired:
        record_scheduler_error_metric(campaign_id, "CONCURRENCY_LOCK_ACQUISITION_FAILED")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Campaign '{campaign_id}' is currently executing. Overlapping runs are prevented."
        )

    try:
        campaign_run_id = f"crun-{uuid.uuid4().hex[:12]}"
        started_at = datetime.now(timezone.utc)

        # 1. Execute Validation Suite
        categories = campaign.category_filter if campaign.category_filter else None
        report = await run_security_validation_suite(
            categories=categories,
            created_by=f"campaign:{user}",
            custom_client=custom_client
        )

        current_run_id = report.run_id
        current_score = report.security_score
        current_results = report.test_results

        # 2. Fetch Baseline Run & Persisted Results (if baseline is configured)
        baseline_run_id = campaign.baseline_run_id
        baseline_results = []
        baseline_score = None

        if baseline_run_id:
            stmt_b_run = select(SecurityTestRunModel).where(SecurityTestRunModel.run_id == baseline_run_id)
            res_b_run = await db.execute(stmt_b_run)
            b_run_row = res_b_run.scalar_one_or_none()
            if b_run_row:
                baseline_score = b_run_row.security_score

            stmt_b_res = select(SecurityTestResultModel).where(SecurityTestResultModel.run_id == baseline_run_id)
            res_b_res = await db.execute(stmt_b_res)
            baseline_results = res_b_res.scalars().all()

        # 3. Perform Baseline Comparison by test_id
        comparison = compare_runs_with_baseline(
            campaign_id=campaign_id,
            campaign_run_id=campaign_run_id,
            current_run_id=current_run_id,
            current_results=current_results,
            current_score=current_score,
            current_policy_version=report.policy_version,
            baseline_run_id=baseline_run_id,
            baseline_results=baseline_results,
            baseline_score=baseline_score
        )

        # If no baseline was set previously, establish current run as initial baseline
        if not campaign.baseline_run_id:
            campaign.baseline_run_id = current_run_id

        # 4. Determine Campaign Run Status
        if comparison.regression_detected:
            run_status = "COMPLETED_WITH_REGRESSIONS"
        elif report.status in ("COMPLETED_WITH_FAILURES", "COMPLETED_WITH_ERRORS"):
            run_status = report.status
        else:
            run_status = "COMPLETED"

        completed_at = datetime.now(timezone.utc)

        # 5. Persist Campaign Run Header
        campaign_run_row = SecurityCampaignRunModel(
            campaign_run_id=campaign_run_id,
            campaign_id=campaign_id,
            run_id=current_run_id,
            started_at=started_at,
            completed_at=completed_at,
            status=run_status,
            total_tests=report.summary.get("total_tests", 0),
            passed_tests=report.summary.get("passed_tests", 0),
            failed_tests=report.summary.get("failed_tests", 0),
            error_tests=report.summary.get("error_tests", 0),
            skipped_tests=report.summary.get("skipped_tests", 0),
            security_score=current_score,
            baseline_score=comparison.baseline_score,
            score_delta=comparison.score_delta,
            regression_detected=comparison.regression_detected,
            created_by=user,
            policy_version=report.policy_version
        )
        db.add(campaign_run_row)

        # 6. Persist Regressions & Record Metrics / SIEM Events
        for reg in comparison.regressions:
            reg_row = SecurityRegressionModel(
                regression_id=reg.regression_id,
                campaign_run_id=campaign_run_id,
                campaign_id=campaign_id,
                test_id=reg.test_id,
                category=reg.category,
                severity=reg.severity,
                previous_status=reg.previous_status,
                current_status=reg.current_status,
                previous_score=reg.previous_score,
                current_score=reg.current_score,
                score_delta=reg.score_delta,
                policy_version=reg.policy_version,
                baseline_run_id=reg.baseline_run_id,
                current_run_id=reg.current_run_id,
                description=reg.description,
                created_at=reg.created_at
            )
            db.add(reg_row)

            # Prometheus metric
            record_regression_detected_metric(reg.category, reg.severity)

            # SIEM security event
            log_security_event(
                event_type="CAMPAIGN_REGRESSION_DETECTED",
                request_id=f"reg-{reg.regression_id}",
                action="BLOCK",
                response_status=500,
                user=user,
                role="security-campaign",
                threat_type=reg.category,
                risk_score=95 if reg.severity in ("CRITICAL", "HIGH") else 75
            )

        # Record overall campaign metrics
        record_campaign_run_metric(run_status)
        record_campaign_score_delta_metric(comparison.score_delta)
        set_campaign_security_score_metrics(campaign_id, current_score, comparison.score_delta)

        # Update campaign record
        campaign.last_run_id = current_run_id
        campaign.updated_at = completed_at
        await db.commit()
        await db.refresh(campaign_run_row)

        log_security_event(
            event_type="CAMPAIGN_RUN_COMPLETED",
            request_id=f"crun-{campaign_run_id}",
            action="ALLOW",
            response_status=200,
            user=user,
            role="security-campaign",
            risk_score=max(0, int(-comparison.score_delta)) if comparison.score_delta < 0 else 0
        )

        run_summary = CampaignRunSummary(
            campaign_run_id=campaign_run_row.campaign_run_id,
            campaign_id=campaign_run_row.campaign_id,
            run_id=campaign_run_row.run_id,
            started_at=campaign_run_row.started_at,
            completed_at=campaign_run_row.completed_at,
            status=campaign_run_row.status,
            total_tests=campaign_run_row.total_tests,
            passed_tests=campaign_run_row.passed_tests,
            failed_tests=campaign_run_row.failed_tests,
            error_tests=campaign_run_row.error_tests,
            skipped_tests=campaign_run_row.skipped_tests,
            security_score=campaign_run_row.security_score,
            baseline_score=campaign_run_row.baseline_score,
            score_delta=campaign_run_row.score_delta,
            regression_detected=campaign_run_row.regression_detected,
            created_by=campaign_run_row.created_by,
            policy_version=campaign_run_row.policy_version or "1.0.0"
        )

        return run_summary, comparison
    finally:
        await release_campaign_lock(campaign_id)



async def get_campaign_history(
    db: AsyncSession,
    campaign_id: str,
    limit: int = 20
) -> List[CampaignRunSummary]:
    """
    Retrieve historical runs for a campaign.
    """
    stmt = (
        select(SecurityCampaignRunModel)
        .where(SecurityCampaignRunModel.campaign_id == campaign_id)
        .order_by(desc(SecurityCampaignRunModel.started_at))
        .limit(limit)
    )
    res = await db.execute(stmt)
    rows = res.scalars().all()

    return [
        CampaignRunSummary(
            campaign_run_id=r.campaign_run_id,
            campaign_id=r.campaign_id,
            run_id=r.run_id,
            started_at=r.started_at,
            completed_at=r.completed_at,
            status=r.status,
            total_tests=r.total_tests,
            passed_tests=r.passed_tests,
            failed_tests=r.failed_tests,
            error_tests=r.error_tests,
            skipped_tests=r.skipped_tests,
            security_score=r.security_score,
            baseline_score=r.baseline_score,
            score_delta=r.score_delta,
            regression_detected=r.regression_detected,
            created_by=r.created_by,
            policy_version=r.policy_version or "1.0.0"
        )
        for r in rows
    ]


async def get_campaign_regressions(
    db: AsyncSession,
    campaign_id: str,
    limit: int = 50
) -> List[RegressionItem]:
    """
    Retrieve recorded regressions for a campaign.
    """
    stmt = (
        select(SecurityRegressionModel)
        .where(SecurityRegressionModel.campaign_id == campaign_id)
        .order_by(desc(SecurityRegressionModel.created_at))
        .limit(limit)
    )
    res = await db.execute(stmt)
    rows = res.scalars().all()

    return [
        RegressionItem(
            regression_id=r.regression_id,
            campaign_run_id=r.campaign_run_id,
            campaign_id=r.campaign_id,
            test_id=r.test_id,
            category=r.category,
            severity=r.severity,
            previous_status=r.previous_status,
            current_status=r.current_status,
            previous_score=r.previous_score,
            current_score=r.current_score,
            score_delta=r.score_delta,
            policy_version=r.policy_version or "1.0.0",
            baseline_run_id=r.baseline_run_id,
            current_run_id=r.current_run_id,
            description=r.description,
            created_at=r.created_at
        )
        for r in rows
    ]


async def _get_latest_campaign_run(
    db: AsyncSession,
    campaign_id: str
) -> Optional[SecurityCampaignRunModel]:
    stmt = (
        select(SecurityCampaignRunModel)
        .where(SecurityCampaignRunModel.campaign_id == campaign_id)
        .order_by(desc(SecurityCampaignRunModel.started_at))
        .limit(1)
    )
    res = await db.execute(stmt)
    return res.scalar_one_or_none()


def _to_campaign_summary(
    row: SecurityCampaignModel,
    latest_run: Optional[SecurityCampaignRunModel] = None
) -> CampaignSummary:
    return CampaignSummary(
        campaign_id=row.campaign_id,
        name=row.name,
        description=row.description,
        status=row.status,
        created_by=row.created_by,
        created_at=row.created_at,
        updated_at=row.updated_at,
        last_run_id=row.last_run_id,
        schedule_enabled=bool(row.schedule_enabled),
        schedule_interval=row.schedule_interval,
        category_filter=row.category_filter or [],
        policy_version=row.policy_version or "1.0.0",
        baseline_run_id=row.baseline_run_id,
        latest_score=latest_run.security_score if latest_run else None,
        baseline_score=latest_run.baseline_score if latest_run else None,
        score_delta=latest_run.score_delta if latest_run else None,
        regression_detected=latest_run.regression_detected if latest_run else None
    )
