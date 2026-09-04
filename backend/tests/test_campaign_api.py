import pytest
import httpx
from backend.main import app

ADMIN_API_KEY = "dev-key-12345"
ANALYST_API_KEY = "test-key-67890"
DEVELOPER_API_KEY = "dev-user-key-54321"


@pytest.mark.asyncio
async def test_campaign_api_rbac_enforcement():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        # 1. Unauthenticated request
        r_unauth = await client.post(
            "/api/campaigns",
            json={"name": "Unauthorized Campaign"}
        )
        assert r_unauth.status_code == 401

        # 2. Developer role denied
        r_dev = await client.post(
            "/api/campaigns",
            headers={"X-API-Key": DEVELOPER_API_KEY},
            json={"name": "Developer Campaign"}
        )
        assert r_dev.status_code == 403

        # 3. Analyst role allowed
        r_analyst = await client.post(
            "/api/campaigns",
            headers={"X-API-Key": ANALYST_API_KEY},
            json={"name": "Analyst Campaign", "category_filter": ["AUTHENTICATION"]}
        )
        assert r_analyst.status_code == 201
        data = r_analyst.json()
        assert data["name"] == "Analyst Campaign"
        campaign_id = data["campaign_id"]

        # 4. Developer denied execution
        r_dev_exec = await client.post(
            f"/api/campaigns/{campaign_id}/execute",
            headers={"X-API-Key": DEVELOPER_API_KEY}
        )
        assert r_dev_exec.status_code == 403

        # 5. Admin allowed execution
        r_admin_exec = await client.post(
            f"/api/campaigns/{campaign_id}/execute",
            headers={"X-API-Key": ADMIN_API_KEY}
        )
        assert r_admin_exec.status_code == 200
        exec_data = r_admin_exec.json()
        assert "run" in exec_data
        assert "comparison" in exec_data
        assert exec_data["run"]["campaign_id"] == campaign_id


@pytest.mark.asyncio
async def test_campaign_api_full_lifecycle():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        headers = {"X-API-Key": ADMIN_API_KEY}

        # 1. Create
        r_create = await client.post(
            "/api/campaigns",
            headers=headers,
            json={
                "name": "Lifecycle Test Campaign",
                "description": "Validating full CRUD lifecycle",
                "category_filter": ["AUTHENTICATION", "RBAC"]
            }
        )
        assert r_create.status_code == 201
        camp = r_create.json()
        camp_id = camp["campaign_id"]

        # 2. Get
        r_get = await client.get(f"/api/campaigns/{camp_id}", headers=headers)
        assert r_get.status_code == 200
        assert r_get.json()["name"] == "Lifecycle Test Campaign"

        # 3. Update
        r_put = await client.put(
            f"/api/campaigns/{camp_id}",
            headers=headers,
            json={"description": "Updated lifecycle description"}
        )
        assert r_put.status_code == 200
        assert r_put.json()["description"] == "Updated lifecycle description"

        # 4. Pause
        r_pause = await client.post(f"/api/campaigns/{camp_id}/pause", headers=headers)
        assert r_pause.status_code == 200
        assert r_pause.json()["status"] == "PAUSED"

        # 5. Resume
        r_resume = await client.post(f"/api/campaigns/{camp_id}/resume", headers=headers)
        assert r_resume.status_code == 200
        assert r_resume.json()["status"] == "ACTIVE"

        # 6. Execute Run 1 (Initial Run)
        r_exec = await client.post(f"/api/campaigns/{camp_id}/execute", headers=headers)
        assert r_exec.status_code == 200
        res_data = r_exec.json()
        assert res_data["run"]["status"] in ("COMPLETED", "COMPLETED_WITH_REGRESSIONS", "COMPLETED_WITH_FAILURES")

        # 7. Check History
        r_runs = await client.get(f"/api/campaigns/{camp_id}/runs", headers=headers)
        assert r_runs.status_code == 200
        assert len(r_runs.json()) >= 1

        # 8. Check Regressions Endpoint
        r_regs = await client.get(f"/api/campaigns/{camp_id}/regressions", headers=headers)
        assert r_regs.status_code == 200
        assert isinstance(r_regs.json(), list)

        # 9. Archive
        r_archive = await client.post(f"/api/campaigns/{camp_id}/archive", headers=headers)
        assert r_archive.status_code == 200
        assert r_archive.json()["status"] == "ARCHIVED"
