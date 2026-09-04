import pytest
from unittest.mock import patch
from datetime import datetime, timezone
from backend.db.database import AsyncSessionLocal
from backend.db.models import SecurityAlertModel
from backend.alerts.engine import _create_and_persist_alert
from backend.services.incident_service import list_incidents


@pytest.mark.asyncio
async def test_alert_creation_triggers_incident_correlation():
    async with AsyncSessionLocal() as session:
        camp_id = f"camp-int-{datetime.now().timestamp()}"
        alert = await _create_and_persist_alert(
            db=session,
            campaign_id=camp_id,
            campaign_run_id=f"crun-{camp_id}",
            alert_type="CAMPAIGN_REGRESSION",
            severity="CRITICAL",
            title="Automated Test Alert for Incident Correlation",
            description="Testing alert-to-incident pipeline",
            score=70.0,
            baseline_score=85.0,
            score_delta=-15.0,
            regression_count=2,
            policy_version="1.0.0",
            created_at=datetime.now(timezone.utc)
        )

        assert alert.alert_id.startswith("alert-")

        # Verify correlated incident was created
        incidents = await list_incidents(session, limit=10)
        matching = [i for i in incidents if i.source_alert_id == alert.alert_id or i.campaign_id == camp_id]
        assert len(matching) >= 1
        assert matching[0].severity in ("CRITICAL", "HIGH")


@pytest.mark.asyncio
async def test_critical_reliability_correlation_failure_does_not_block_alert():
    """
    CRITICAL RELIABILITY TEST (MANDATORY):
    Alert creation succeeds + Incident correlation intentionally fails = Alert still exists and security pipeline remains successful.
    """
    async with AsyncSessionLocal() as session:
        camp_id = f"camp-fail-{datetime.now().timestamp()}"

        # Mock correlate_alert_safe to intentionally raise an unhandled exception
        with patch("backend.services.incident_service.correlate_alert_safe", side_effect=RuntimeError("Intentional DB Correlator Crash")):
            # Alert creation MUST NOT raise or fail
            alert = await _create_and_persist_alert(
                db=session,
                campaign_id=camp_id,
                campaign_run_id=f"crun-{camp_id}",
                alert_type="SECURITY_SCORE_DEGRADATION",
                severity="HIGH",
                title="Resilience Test Alert",
                description="Verifying fail-safe non-blocking alert persistence",
                score=65.0,
                baseline_score=80.0,
                score_delta=-15.0,
                regression_count=1,
                policy_version="1.0.0",
                created_at=datetime.now(timezone.utc)
            )

            # Assert alert was successfully created and persisted in DB
            assert alert is not None
            assert alert.alert_id.startswith("alert-")
            assert alert.status == "OPEN"
            assert alert.severity == "HIGH"

            # Check DB record
            from sqlalchemy import select
            stmt = select(SecurityAlertModel).where(SecurityAlertModel.alert_id == alert.alert_id)
            res = await session.execute(stmt)
            persisted = res.scalar_one_or_none()
            assert persisted is not None
            assert persisted.alert_id == alert.alert_id
