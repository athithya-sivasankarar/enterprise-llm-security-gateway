import pytest
from datetime import datetime, timezone
from backend.db.database import AsyncSessionLocal
from backend.db.models import SecurityTestResultModel, SecurityRegressionModel
from backend.control_coverage.engine import (
    evaluate_security_control_coverage,
    STANDARD_SECURITY_CONTROLS
)


@pytest.mark.asyncio
async def test_control_coverage_all_passing():
    async with AsyncSessionLocal() as session:
        # Seed test results for all 14 categories
        now = datetime.now(timezone.utc)
        run_id = f"test-run-{int(now.timestamp())}"

        for ctrl in STANDARD_SECURITY_CONTROLS:
            for tid in ctrl["tests_mapped"]:
                row = SecurityTestResultModel(
                    run_id=run_id,
                    test_id=tid,
                    category=ctrl["domain"],
                    severity="INFO",
                    status="PASS",
                    error_message=None,
                    created_at=now
                )
                session.add(row)

        await session.commit()

        summary = await evaluate_security_control_coverage(session, run_id=run_id)

        assert summary.total_controls == len(STANDARD_SECURITY_CONTROLS)
        assert summary.tested_controls == len(STANDARD_SECURITY_CONTROLS)
        assert summary.passing_controls == len(STANDARD_SECURITY_CONTROLS)
        assert summary.failing_controls == 0
        assert summary.regression_controls == 0
        assert summary.overall_coverage_pct == 100.0
        assert summary.overall_pass_pct == 100.0
        assert len(summary.gaps) == 0


@pytest.mark.asyncio
async def test_control_coverage_with_failing_and_regression():
    async with AsyncSessionLocal() as session:
        now = datetime.now(timezone.utc)
        run_id = f"test-run-fail-{int(now.timestamp())}"

        # Pass AUTH
        session.add(
            SecurityTestResultModel(
                run_id=run_id,
                test_id="AUTH-001",
                category="AUTHENTICATION",
                severity="CRITICAL",
                status="PASS",
                created_at=now
            )
        )
        # Fail PI
        session.add(
            SecurityTestResultModel(
                run_id=run_id,
                test_id="PI-001",
                category="PROMPT_INJECTION",
                severity="HIGH",
                status="FAIL",
                created_at=now
            )
        )
        # Regression in DLP
        session.add(
            SecurityRegressionModel(
                regression_id=f"reg-{run_id}",
                campaign_run_id=run_id,
                campaign_id="camp-1",
                test_id="DLP-001",
                category="INPUT_DLP",
                severity="CRITICAL",
                previous_status="PASS",
                current_status="FAIL",
                description="DLP regression",
                created_at=now
            )
        )
        await session.commit()

        summary = await evaluate_security_control_coverage(session, run_id=run_id)
        assert summary.control_gaps_count > 0
        gap_types = [g.gap_type for g in summary.gaps]
        assert "CONTROL_FAILING" in gap_types or "CONTROL_REGRESSION" in gap_types
