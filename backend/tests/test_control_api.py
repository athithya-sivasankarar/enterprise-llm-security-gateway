import pytest
import httpx
from backend.main import app

ANALYST_API_KEY = "test-key-67890"


@pytest.mark.asyncio
async def test_control_api_endpoints():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        headers = {"X-API-Key": ANALYST_API_KEY}

        # 1. List Controls
        r_list = await client.get("/api/controls", headers=headers)
        assert r_list.status_code == 200
        controls = r_list.json()
        assert len(controls) >= 14

        # 2. Get Control Detail
        ctrl_id = controls[0]["control_id"]
        r_get = await client.get(f"/api/controls/{ctrl_id}", headers=headers)
        assert r_get.status_code == 200
        assert r_get.json()["control_id"] == ctrl_id

        # 3. Control Coverage
        r_cov = await client.get("/api/controls/coverage", headers=headers)
        assert r_cov.status_code == 200
        assert "overall_coverage_pct" in r_cov.json()
        assert len(r_cov.json()["matrix"]) >= 14

        # 4. Control Gaps
        r_gaps = await client.get("/api/controls/gaps", headers=headers)
        assert r_gaps.status_code == 200
        assert isinstance(r_gaps.json(), list)
