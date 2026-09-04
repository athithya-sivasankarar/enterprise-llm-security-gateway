import pytest
import httpx
from backend.main import app

ANALYST_API_KEY = "test-key-67890"


@pytest.mark.asyncio
async def test_exposure_api_endpoints():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        headers = {"X-API-Key": ANALYST_API_KEY}

        # 1. Create Exposure
        r_create = await client.post(
            "/api/exposures",
            headers=headers,
            json={
                "asset_id": "ast-api-chat",
                "category": "SECRET_LEAKAGE",
                "severity": "CRITICAL",
                "exposure_type": "CONTROL_GAP",
                "description": "API Test Exposure for Secret Redaction Filter",
                "has_active_regression": True
            }
        )
        assert r_create.status_code == 201
        exp_id = r_create.json()["exposure_id"]

        # 2. Get Detail
        r_get = await client.get(f"/api/exposures/{exp_id}", headers=headers)
        assert r_get.status_code == 200
        assert r_get.json()["exposure_id"] == exp_id

        # 3. List
        r_list = await client.get("/api/exposures", headers=headers)
        assert r_list.status_code == 200
        assert len(r_list.json()) >= 1

        # 4. Summary
        r_sum = await client.get("/api/exposures/summary", headers=headers)
        assert r_sum.status_code == 200
        assert r_sum.json()["open_exposures"] >= 1

        # 5. Resolve
        r_res = await client.post(
            f"/api/exposures/{exp_id}/resolve",
            headers=headers,
            json={"reason": "Updated API key redaction regex pattern"}
        )
        assert r_res.status_code == 200
        assert r_res.json()["status"] == "RESOLVED"
