import pytest
from backend.db.database import AsyncSessionLocal
from backend.governance.assurance import evaluate_control_assurance, get_control_assurance, CORE_SECURITY_CONTROLS


@pytest.mark.asyncio
async def test_control_assurance_evaluation_all_controls():
    async with AsyncSessionLocal() as session:
        assurances = await evaluate_control_assurance(session, actor="test-runner")
        assert len(assurances) == len(CORE_SECURITY_CONTROLS)

        for a in assurances:
            assert a.control_id in CORE_SECURITY_CONTROLS
            assert 0.0 <= a.coverage_percentage <= 100.0
            assert 0.0 <= a.effectiveness_score <= 100.0
            assert a.last_status in ("PASS", "DEGRADED", "GAP")
            assert a.risk_score >= 0


@pytest.mark.asyncio
async def test_control_assurance_single_control_lookup():
    async with AsyncSessionLocal() as session:
        res = await get_control_assurance(session, control_id="INPUT_DLP")
        assert len(res) >= 1
        dlp = res[0]
        assert dlp.control_id == "INPUT_DLP"
        assert dlp.name is not None
        assert dlp.domain == "INPUT_DLP"
