import pytest
import httpx
from backend.main import app

ADMIN_API_KEY = "dev-key-12345"
ANALYST_API_KEY = "test-key-67890"
DEVELOPER_API_KEY = "dev-user-key-54321"


@pytest.mark.asyncio
async def test_scheduler_api_rbac_enforcement():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        # Create campaign first as admin
        r_camp = await client.post(
            "/api/campaigns",
            headers={"X-API-Key": ADMIN_API_KEY},
            json={"name": "Scheduler RBAC Campaign", "category_filter": ["AUTHENTICATION"]}
        )
        assert r_camp.status_code == 201
        camp_id = r_camp.json()["campaign_id"]

        # 1. Unauthenticated schedule create -> 401
        r_unauth = await client.post(
            f"/api/scheduler/campaigns/{camp_id}",
            json={"schedule_type": "INTERVAL", "interval_minutes": 60}
        )
        assert r_unauth.status_code == 401

        # 2. Developer schedule create -> 403
        r_dev = await client.post(
            f"/api/scheduler/campaigns/{camp_id}",
            headers={"X-API-Key": DEVELOPER_API_KEY},
            json={"schedule_type": "INTERVAL", "interval_minutes": 60}
        )
        assert r_dev.status_code == 403

        # 3. Analyst schedule create -> 201
        r_analyst = await client.post(
            f"/api/scheduler/campaigns/{camp_id}",
            headers={"X-API-Key": ANALYST_API_KEY},
            json={"schedule_type": "INTERVAL", "interval_minutes": 120}
        )
        assert r_analyst.status_code == 201
        assert r_analyst.json()["interval_minutes"] == 120

        # 4. Developer trigger -> 403
        r_dev_trig = await client.post(
            f"/api/scheduler/campaigns/{camp_id}/trigger",
            headers={"X-API-Key": DEVELOPER_API_KEY}
        )
        assert r_dev_trig.status_code == 403

        # 5. Admin trigger -> 200
        r_admin_trig = await client.post(
            f"/api/scheduler/campaigns/{camp_id}/trigger",
            headers={"X-API-Key": ADMIN_API_KEY}
        )
        assert r_admin_trig.status_code == 200
        assert "run" in r_admin_trig.json()


@pytest.mark.asyncio
async def test_scheduler_api_safety_rejection_for_unsafe_intervals():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        # Create campaign
        r_camp = await client.post(
            "/api/campaigns",
            headers={"X-API-Key": ADMIN_API_KEY},
            json={"name": "Safety Policy API Campaign"}
        )
        assert r_camp.status_code == 201
        camp_id = r_camp.json()["campaign_id"]

        # 1. Reject interval < 60m
        r_short = await client.post(
            f"/api/scheduler/campaigns/{camp_id}",
            headers={"X-API-Key": ADMIN_API_KEY},
            json={"schedule_type": "INTERVAL", "interval_minutes": 30}
        )
        assert r_short.status_code == 400
        assert "safety policy" in r_short.json()["detail"]

        # 2. Reject unsafe cron
        r_cron_unsafe = await client.post(
            f"/api/scheduler/campaigns/{camp_id}",
            headers={"X-API-Key": ADMIN_API_KEY},
            json={"schedule_type": "CRON", "cron_expression": "*/5 * * * *"}
        )
        assert r_cron_unsafe.status_code == 400
        assert "safety policy" in r_cron_unsafe.json()["detail"]


@pytest.mark.asyncio
async def test_scheduler_api_full_lifecycle():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        headers = {"X-API-Key": ADMIN_API_KEY}

        # 1. Create Campaign & Schedule
        r_camp = await client.post(
            "/api/campaigns",
            headers=headers,
            json={"name": "Lifecycle Schedule Campaign"}
        )
        camp_id = r_camp.json()["campaign_id"]

        r_create = await client.post(
            f"/api/scheduler/campaigns/{camp_id}",
            headers=headers,
            json={"schedule_type": "CRON", "cron_expression": "0 * * * *"}
        )
        assert r_create.status_code == 201
        assert r_create.json()["cron_expression"] == "0 * * * *"

        # 2. Get Schedule
        r_get = await client.get(f"/api/scheduler/campaigns/{camp_id}", headers=headers)
        assert r_get.status_code == 200

        # 3. Disable Schedule
        r_dis = await client.post(f"/api/scheduler/campaigns/{camp_id}/disable", headers=headers)
        assert r_dis.status_code == 200
        assert r_dis.json()["enabled"] is False

        # 4. Enable Schedule
        r_en = await client.post(f"/api/scheduler/campaigns/{camp_id}/enable", headers=headers)
        assert r_en.status_code == 200
        assert r_en.json()["enabled"] is True

        # 5. Status & Next Runs
        r_stat = await client.get("/api/scheduler/status", headers=headers)
        assert r_stat.status_code == 200
        assert "total_schedules" in r_stat.json()

        r_next = await client.get("/api/scheduler/next-runs", headers=headers)
        assert r_next.status_code == 200
        assert isinstance(r_next.json(), list)

        # 6. Delete Schedule
        r_del = await client.delete(f"/api/scheduler/campaigns/{camp_id}", headers=headers)
        assert r_del.status_code == 200
        assert r_del.json()["status"] == "deleted"
