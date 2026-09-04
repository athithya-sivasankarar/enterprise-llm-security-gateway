import pytest
from dataclasses import dataclass
from typing import List, Optional

from backend.db.database import AsyncSessionLocal
from backend.alerts.engine import (
    evaluate_campaign_alerts,
    record_execution_error_alert,
    record_scheduler_error_alert
)
from backend.alerts.models import AlertType, AlertSeverity, AlertStatus


@dataclass
class MockRegression:
    test_id: str
    category: str
    severity: str
    previous_status: str
    current_status: str


@dataclass
class MockComparison:
    regression_detected: bool
    regressions: List[MockRegression]
    baseline_score: Optional[float]
    score_delta: Optional[float]


@dataclass
class MockRunSummary:
    security_score: float
    policy_version: str = "1.0.0"


@pytest.mark.asyncio
async def test_alert_engine_regression_rule():
    import uuid
    async with AsyncSessionLocal() as session:
        campaign_id = f"test-alert-camp-{uuid.uuid4().hex[:8]}"
        comp = MockComparison(
            regression_detected=True,
            regressions=[
                MockRegression(test_id="INJ-001", category="PROMPT_INJECTION", severity="CRITICAL", previous_status="PASS", current_status="FAIL")
            ],
            baseline_score=100.0,
            score_delta=-10.0
        )
        run_sum = MockRunSummary(security_score=90.0)

        alerts = await evaluate_campaign_alerts(
            db=session,
            campaign_id=campaign_id,
            campaign_run_id="crun-1",
            run_summary=run_sum,
            comparison=comp
        )

        assert len(alerts) >= 1
        reg_alert = next((a for a in alerts if a.alert_type == AlertType.CAMPAIGN_REGRESSION.value), None)
        assert reg_alert is not None
        assert reg_alert.severity == AlertSeverity.CRITICAL.value
        assert "INJ-001" in reg_alert.description
        assert reg_alert.status == AlertStatus.OPEN.value


@pytest.mark.asyncio
async def test_alert_engine_score_degradation_rule():
    import uuid
    async with AsyncSessionLocal() as session:
        campaign_id = f"test-alert-camp-{uuid.uuid4().hex[:8]}"
        comp = MockComparison(
            regression_detected=False,
            regressions=[],
            baseline_score=100.0,
            score_delta=-8.0  # Drops by 8%, exceeds -5% threshold
        )
        run_sum = MockRunSummary(security_score=92.0)

        alerts = await evaluate_campaign_alerts(
            db=session,
            campaign_id=campaign_id,
            campaign_run_id="crun-2",
            run_summary=run_sum,
            comparison=comp
        )

        assert len(alerts) == 1
        deg_alert = alerts[0]
        assert deg_alert.alert_type == AlertType.SECURITY_SCORE_DEGRADATION.value
        assert deg_alert.score_delta == -8.0


@pytest.mark.asyncio
async def test_alert_engine_deduplication():
    import uuid
    async with AsyncSessionLocal() as session:
        campaign_id = f"test-alert-camp-{uuid.uuid4().hex[:8]}"
        comp = MockComparison(
            regression_detected=True,
            regressions=[
                MockRegression(test_id="DLP-001", category="INPUT_DLP", severity="HIGH", previous_status="PASS", current_status="FAIL")
            ],
            baseline_score=100.0,
            score_delta=-5.0
        )
        run_sum = MockRunSummary(security_score=95.0)

        # Run 1: Generates alert
        alerts_1 = await evaluate_campaign_alerts(session, campaign_id, "crun-3a", run_sum, comp)
        assert len(alerts_1) >= 1

        # Run 2 with same regression: Deduplicated, does not generate duplicate alert
        alerts_2 = await evaluate_campaign_alerts(session, campaign_id, "crun-3b", run_sum, comp)
        assert len(alerts_2) == 0



@pytest.mark.asyncio
async def test_alert_engine_error_alerts():
    async with AsyncSessionLocal() as session:
        exec_alert = await record_execution_error_alert(
            db=session,
            campaign_id="test-err-camp",
            error_message="Gateway timeout during validation"
        )
        assert exec_alert.alert_type == AlertType.CAMPAIGN_EXECUTION_ERROR.value
        assert exec_alert.severity == AlertSeverity.HIGH.value

        sched_alert = await record_scheduler_error_alert(
            db=session,
            campaign_id="test-err-camp",
            error_message="Redis lock connection refused"
        )
        assert sched_alert.alert_type == AlertType.SCHEDULER_ERROR.value
        assert sched_alert.severity == AlertSeverity.MEDIUM.value
