import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from backend.db.database import get_db
from backend.db.models import (
    SecurityTestRunModel,
    SecurityTestResultModel,
    SecurityTestFindingModel
)
from backend.security.rbac import require_dashboard_access
from backend.redteam.models import (
    RunSecurityTestsRequest,
    SecurityReport,
    SecurityTestRunSummary,
    SecurityTestFinding,
    SecurityTestResult,
    CategorySummary
)
from backend.redteam.catalog import TEST_CATALOG, get_test_catalog
from backend.redteam.runner import run_security_validation_suite
from backend.redteam.reporter import generate_security_report
from backend.redteam.categories import TestCategory

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/security-tests", tags=["Security Validation & Red-Team"])


@router.post("/run", response_model=SecurityReport)
async def run_security_tests(
    req: Optional[RunSecurityTestsRequest] = None,
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Trigger an automated security validation run across specified or all categories.
    Strictly restricted to Admin and Security Analyst roles (Developer receives HTTP 403).
    Deterministic: Defaults to mock-model; zero external API charges.
    """
    categories = req.categories if req and req.categories else None
    
    # Validate category names if provided
    if categories:
        valid_cats = {c.value.upper() for c in TestCategory}
        for cat in categories:
            if cat.upper() not in valid_cats:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid category '{cat}'. Valid categories are: {sorted(list(valid_cats))}"
                )

    username = user_data.get("user", "authenticated-user")
    
    try:
        report = await run_security_validation_suite(
            categories=categories,
            created_by=username
        )
        return report
    except Exception as exc:
        logger.error(f"Security validation suite execution failed: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Security validation execution failed: {str(exc)}"
        )


@router.get("/runs", response_model=List[SecurityTestRunSummary])
async def list_security_test_runs(
    limit: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Retrieve historical security test runs.
    Restricted to Admin and Analyst roles.
    """
    try:
        stmt = select(SecurityTestRunModel).order_by(desc(SecurityTestRunModel.started_at)).limit(limit)
        res = await db.execute(stmt)
        rows = res.scalars().all()

        return [
            SecurityTestRunSummary(
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
                policy_version=r.policy_version or "1.0.0",
                created_by=r.created_by
            )
            for r in rows
        ]
    except Exception as exc:
        logger.error(f"Failed to fetch security test runs: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve security test runs"
        )


@router.get("/runs/{run_id}", response_model=SecurityTestRunSummary)
async def get_security_test_run(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Get summary status for a specific test run ID.
    """
    stmt = select(SecurityTestRunModel).where(SecurityTestRunModel.run_id == run_id)
    res = await db.execute(stmt)
    row = res.scalar_one_or_none()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security test run '{run_id}' not found."
        )

    return SecurityTestRunSummary(
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
        policy_version=row.policy_version or "1.0.0",
        created_by=row.created_by
    )


@router.get("/runs/{run_id}/report", response_model=SecurityReport)
async def get_security_test_report(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Generate and return full detailed security validation report for a historical run.
    """
    # 1. Fetch Run Header
    stmt_run = select(SecurityTestRunModel).where(SecurityTestRunModel.run_id == run_id)
    res_run = await db.execute(stmt_run)
    run_row = res_run.scalar_one_or_none()

    if not run_row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security test run '{run_id}' not found."
        )

    # 2. Fetch Results
    stmt_res = select(SecurityTestResultModel).where(SecurityTestResultModel.run_id == run_id).order_by(SecurityTestResultModel.id)
    res_results = await db.execute(stmt_res)
    result_rows = res_results.scalars().all()

    # 3. Fetch Findings
    stmt_find = select(SecurityTestFindingModel).where(SecurityTestFindingModel.run_id == run_id).order_by(SecurityTestFindingModel.id)
    res_findings = await db.execute(stmt_find)
    finding_rows = res_findings.scalars().all()

    test_results = [
        SecurityTestResult(
            run_id=r.run_id,
            test_id=r.test_id,
            category=r.category,
            status=r.status,
            severity=r.severity,
            expected_action=r.expected_action,
            actual_action=r.actual_action,
            expected_status=r.expected_status,
            actual_status=r.actual_status,
            threat_type=r.threat_type,
            latency_ms=r.latency_ms,
            policy_version=r.policy_version or "1.0.0",
            error_message=r.error_message,
            created_at=r.created_at
        )
        for r in result_rows
    ]

    findings = [
        SecurityTestFinding(
            finding_id=f.finding_id,
            run_id=f.run_id,
            test_id=f.test_id,
            category=f.category,
            severity=f.severity,
            title=f.title,
            description=f.description,
            expected_behavior=f.expected_behavior,
            actual_behavior=f.actual_behavior,
            endpoint=f.endpoint,
            policy_version=f.policy_version or "1.0.0",
            created_at=f.created_at
        )
        for f in finding_rows
    ]

    return generate_security_report(
        run_id=run_row.run_id,
        status=run_row.status,
        policy_version=run_row.policy_version or "1.0.0",
        started_at=run_row.started_at,
        completed_at=run_row.completed_at,
        created_by=run_row.created_by,
        results=test_results,
        findings=findings
    )


@router.get("/findings", response_model=List[SecurityTestFinding])
async def list_security_findings(
    limit: int = Query(default=50, ge=1, le=200),
    severity: Optional[str] = Query(default=None),
    category: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    List historical security findings for SOC review and triage.
    Restricted to Admin and Analyst roles.
    """
    try:
        query = select(SecurityTestFindingModel).order_by(desc(SecurityTestFindingModel.created_at)).limit(limit)
        if severity:
            query = query.where(SecurityTestFindingModel.severity == severity.upper())
        if category:
            query = query.where(SecurityTestFindingModel.category == category.upper())

        res = await db.execute(query)
        rows = res.scalars().all()

        return [
            SecurityTestFinding(
                finding_id=f.finding_id,
                run_id=f.run_id,
                test_id=f.test_id,
                category=f.category,
                severity=f.severity,
                title=f.title,
                description=f.description,
                expected_behavior=f.expected_behavior,
                actual_behavior=f.actual_behavior,
                endpoint=f.endpoint,
                policy_version=f.policy_version or "1.0.0",
                created_at=f.created_at
            )
            for f in rows
        ]
    except Exception as exc:
        logger.error(f"Failed to retrieve security findings: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve security findings"
        )


@router.get("/catalog")
async def get_catalog(
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Inspect server-controlled test catalog metadata.
    """
    return {
        "total": len(TEST_CATALOG),
        "categories": [c.value for c in TestCategory],
        "tests": [
            {
                "test_id": t.test_id,
                "name": t.name,
                "category": t.category.value,
                "description": t.description,
                "severity": t.severity.value,
                "endpoint": t.endpoint,
                "method": t.method,
                "model": t.model,
                "expected_status": t.expected_status,
                "expected_action": t.expected_action
            }
            for t in TEST_CATALOG
        ]
    }
