import pytest
from datetime import datetime, timezone
from backend.db.database import AsyncSessionLocal
from backend.services.asset_service import get_asset, get_asset_coverage
from backend.services.control_service import get_control_coverage
from backend.services.threatintel_service import match_intelligence_for_target
from backend.services.exposure_service import create_exposure, get_exposure_summary, ExposureCreateRequest
from backend.threatintel.models import ThreatIntelMatchRequest
from backend.alerts.engine import _create_and_persist_alert
from backend.services.incident_service import create_incident, IncidentCreateRequest


@pytest.mark.asyncio
async def test_step20_full_integration_pipeline():
    """
    End-to-end integration test:
    Mock Model -> Prompt Injection Test Finding -> Campaign Regression ->
    SOC Alert -> Security Incident -> Affected LLM Asset -> Control Coverage Gap ->
    Threat Intel Match -> Security Exposure -> Risk Score -> Resolution.
    """
    async with AsyncSessionLocal() as session:
        now = datetime.now(timezone.utc)
        camp_id = f"camp-s20-{int(now.timestamp())}"

        # 1. Trigger Alert & Incident (Step 17/19)
        alert = await _create_and_persist_alert(
            db=session,
            campaign_id=camp_id,
            campaign_run_id=f"crun-{camp_id}",
            alert_type="CAMPAIGN_REGRESSION",
            severity="CRITICAL",
            title="Step 20 Integration Regression Alert",
            description="Detected prompt injection vulnerability during campaign",
            score=65.0,
            baseline_score=90.0,
            score_delta=-25.0,
            regression_count=1,
            policy_version="1.0.0",
            created_at=now
        )
        assert alert.alert_id.startswith("alert-")

        inc = await create_incident(
            session,
            IncidentCreateRequest(
                title="Prompt Injection Incident on Mock Model",
                description="Investigating model vulnerability",
                severity="CRITICAL",
                campaign_id=camp_id
            ),
            user="soc-analyst"
        )
        assert inc.incident_id.startswith("inc-")

        # 2. Asset Discovery & Coverage (Step 20)
        asset = await get_asset(session, "ast-llm-mock")
        assert asset.asset_type == "LLM_MODEL"

        cov = await get_asset_coverage(session, asset.asset_id)
        assert cov.coverage_pct >= 0.0

        # 3. Security Control Coverage (Step 20)
        ctrl_cov = await get_control_coverage(session)
        assert ctrl_cov.total_controls == 14
        assert ctrl_cov.overall_coverage_pct >= 0.0

        # 4. Threat Intelligence Matching (Step 20)
        matches = await match_intelligence_for_target(
            session,
            ThreatIntelMatchRequest(
                category="PROMPT_INJECTION",
                incident_id=inc.incident_id,
                asset_id=asset.asset_id
            ),
            user="soc-analyst"
        )
        assert len(matches) >= 1
        matched_indicators = [m.indicator for m in matches]
        assert any(ind in ("AML.T0054", "LLM01", "CWE-77", "CVE-2024-9999") for ind in matched_indicators)
        assert matches[0].relevance_score >= 40

        # 5. Security Exposure Creation & Enterprise Risk (Step 20)
        exp = await create_exposure(
            session,
            ExposureCreateRequest(
                asset_id=asset.asset_id,
                category="PROMPT_INJECTION",
                severity="CRITICAL",
                exposure_type="ACTIVE_REGRESSION",
                description="Active regression in prompt injection filter exposed on mock LLM",
                source_id=inc.incident_id,
                has_active_regression=True,
                has_open_incident=True,
                has_control_gap=True,
                threat_intel_confidence=0.95
            ),
            user="soc-analyst"
        )
        assert exp.exposure_id.startswith("exp-")
        assert exp.risk_score >= 80

        # 6. Exposure Summary & Enterprise Risk Classification
        exp_summary = await get_exposure_summary(session)
        assert exp_summary.open_exposures >= 1
        assert exp_summary.enterprise_risk_score >= 80
        assert exp_summary.risk_classification == "CRITICAL"
