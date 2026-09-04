import pytest
import httpx
from backend.main import app

ANALYST_API_KEY = "test-key-67890"


@pytest.mark.asyncio
async def test_asset_api_endpoints():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        headers = {"X-API-Key": ANALYST_API_KEY}

        # 1. Create
        r_create = await client.post(
            "/api/assets",
            headers=headers,
            json={
                "asset_type": "LLM_MODEL",
                "name": "API Test Model",
                "environment": "production",
                "provider": "mock",
                "model": "mock-api",
                "criticality": "HIGH"
            }
        )
        assert r_create.status_code == 201
        asset_id = r_create.json()["asset_id"]

        # 2. Get Detail
        r_get = await client.get(f"/api/assets/{asset_id}", headers=headers)
        assert r_get.status_code == 200
        assert r_get.json()["asset_id"] == asset_id

        # 3. Update
        r_put = await client.put(
            f"/api/assets/{asset_id}",
            headers=headers,
            json={"criticality": "CRITICAL"}
        )
        assert r_put.status_code == 200
        assert r_put.json()["criticality"] == "CRITICAL"

        # 4. List
        r_list = await client.get("/api/assets", headers=headers)
        assert r_list.status_code == 200
        assert len(r_list.json()) >= 1

        # 5. Summary
        r_sum = await client.get("/api/assets/summary", headers=headers)
        assert r_sum.status_code == 200
        assert r_sum.json()["total_assets"] >= 1

        # 6. Attack Surface Graph
        r_graph = await client.get("/api/assets/attack-surface", headers=headers)
        assert r_graph.status_code == 200
        assert len(r_graph.json()["nodes"]) >= 1

        # 7. Asset Coverage
        r_cov = await client.get(f"/api/assets/{asset_id}/coverage", headers=headers)
        assert r_cov.status_code == 200
        assert "coverage_pct" in r_cov.json()
