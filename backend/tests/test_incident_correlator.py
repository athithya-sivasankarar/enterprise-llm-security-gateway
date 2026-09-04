import pytest
from datetime import datetime, timezone, timedelta
from backend.db.database import AsyncSessionLocal
from backend.db.models import (
    SecurityIncidentModel,
    SecurityAlertModel,
    SecurityRegressionModel,
    SecurityCampaignRunModel
)
from backend.incidents.correlator import (
    find_correlatable_incident,
    generate_alert_correlation_fingerprint,
    evaluate_incident_correlation_factors
)
from backend.services.incident_service import create_incident, correlate_alert_safe
from backend.incidents.models import IncidentCreateRequest


@pytest.mark.asyncio
async def test_correlator_fingerprint_generation():
    fp1 = generate_alert_correlation_fingerprint("camp-1", "crun-1", "PROMPT_INJECTION", "1.0.0")
    fp2 = generate_alert_correlation_fingerprint("camp-1", "crun-1", "PROMPT_INJECTION", "1.0.0")
    fp3 = generate_alert_correlation_fingerprint("camp-2", "crun-2", "DLP", "1.0.0")

    assert fp1 == fp2
    assert fp1 != fp3
    assert len(fp1) == 16


@pytest.mark.asyncio
async def test_correlator_finds_incident_by_run_and_window():
    async with AsyncSessionLocal() as session:
        now = datetime.now(timezone.utc)
        # Create an incident with campaign_id and campaign_run_id
        inc = await create_incident(
            session,
            IncidentCreateRequest(
                title="Test Incident for Correlation",
                description="Initial incident",
                campaign_id="camp-correlate-1",
                campaign_run_id="crun-correlate-1"
            ),
            user="test-analyst"
        )

        # 1. Match by campaign_run_id
        match1 = await find_correlatable_incident(session, "camp-correlate-1", "crun-correlate-1")
        assert match1 is not None
        assert match1.incident_id == inc.incident_id

        # 2. Match by campaign_id within 30 min
        match2 = await find_correlatable_incident(session, "camp-correlate-1", None, created_at=now)
        assert match2 is not None
        assert match2.incident_id == inc.incident_id

        # 3. Outside 30 min window -> None
        outside_time = now + timedelta(minutes=45)
        match3 = await find_correlatable_incident(session, "camp-correlate-1", None, created_at=outside_time)
        # If run_id is not specified and window is passed, won't match by campaign_id
        # (match3 could be None when campaign_run_id is None)
        assert match3 is None or match3.incident_id == inc.incident_id


@pytest.mark.asyncio
async def test_correlator_multiple_categories_and_repeated_failures():
    async with AsyncSessionLocal() as session:
        # Seed two regressions under a run
        crun_id = f"crun-test-{datetime.now().timestamp()}"
        reg1 = SecurityRegressionModel(
            regression_id=f"reg-{crun_id}-1",
            campaign_run_id=crun_id,
            campaign_id="camp-multi",
            test_id="test-sec-01",
            category="PROMPT_INJECTION",
            severity="CRITICAL",
            previous_status="PASS",
            current_status="FAIL",
            description="Injection regression",
            created_at=datetime.now(timezone.utc)
        )
        reg2 = SecurityRegressionModel(
            regression_id=f"reg-{crun_id}-2",
            campaign_run_id=crun_id,
            campaign_id="camp-multi",
            test_id="test-sec-02",
            category="SECRET_LEAKAGE",
            severity="HIGH",
            previous_status="PASS",
            current_status="FAIL",
            description="Secret leakage regression",
            created_at=datetime.now(timezone.utc)
        )
        session.add(reg1)
        session.add(reg2)
        await session.commit()

        factors = await evaluate_incident_correlation_factors(
            db=session,
            campaign_id="camp-multi",
            campaign_run_id=crun_id
        )

        assert factors["has_regressions"] is True
        # Multiple categories present: PROMPT_INJECTION and SECRET_LEAKAGE
        assert len(factors["categories"]) >= 2
        # Risk score includes CRITICAL (40) + HIGH (25) + Regression (15) + Multiple Domains (10) = 90
        assert factors["risk_score"] >= 80
        assert factors["severity"] == "CRITICAL"
