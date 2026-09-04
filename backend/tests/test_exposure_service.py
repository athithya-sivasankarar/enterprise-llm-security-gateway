import pytest
from backend.db.database import AsyncSessionLocal
from backend.services.exposure_service import (
    create_exposure,
    list_exposures,
    get_exposure,
    resolve_exposure,
    get_exposure_summary,
    ExposureCreateRequest,
    ExposureResolveRequest
)


@pytest.mark.asyncio
async def test_exposure_service_lifecycle():
    async with AsyncSessionLocal() as session:
        # Create
        req = ExposureCreateRequest(
            asset_id="ast-llm-mock",
            category="PROMPT_INJECTION",
            severity="HIGH",
            exposure_type="CONTROL_GAP",
            description="Prompt injection bypass vulnerability test",
            has_active_regression=True,
            has_control_gap=True
        )
        exp = await create_exposure(session, req, user="security-analyst")
        assert exp.exposure_id.startswith("exp-")
        assert exp.status == "OPEN"
        assert exp.risk_score >= 50

        # Get
        fetched = await get_exposure(session, exp.exposure_id)
        assert fetched.exposure_id == exp.exposure_id

        # List
        open_exps = await list_exposures(session, status_filter="OPEN", category="PROMPT_INJECTION")
        assert len(open_exps) >= 1

        # Summary
        summary = await get_exposure_summary(session)
        assert summary.open_exposures >= 1
        assert summary.enterprise_risk_score >= 50

        # Resolve
        resolved = await resolve_exposure(
            session,
            exp.exposure_id,
            ExposureResolveRequest(reason="Tuned injection heuristic threshold"),
            user="security-admin"
        )
        assert resolved.status == "RESOLVED"
