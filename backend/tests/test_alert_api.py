import pytest
import httpx
from backend.main import app
from backend.db.database import AsyncSessionLocal
from backend.alerts.engine import record_execution_error_alert

ADMIN_API_KEY = "dev-key-12345"
ANALYST_API_KEY = "test-key-67890"
DEVELOPER_API_KEY = "dev-user-key-54321"


@pytest.mark.asyncio
async def test_alert_api_rbac_enforcement():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        # Create an alert directly in DB
        async with AsyncSessionLocal() as session:
            alert = await record_execution_error_alert(
                session, "rbac-alert-camp", "Sample execution failure"
            )
            alert_id = alert.alert_id

        # 1. Unauthenticated -> 401
        r_unauth = await client.get("/api/alerts")
        assert r_unauth.status_code == 401

        # 2. Developer -> 403
        r_dev = await client.get("/api/alerts", headers={"X-API-Key": DEVELOPER_API_KEY})
        assert r_dev.status_code == 403

        # 3. Analyst -> 200
        r_analyst = await client.get("/api/alerts", headers={"X-API-Key": ANALYST_API_KEY})
        assert r_analyst.status_code == 200
        assert isinstance(r_analyst.json(), list)

        # 4. Developer acknowledge -> 403
        r_dev_ack = await client.post(
            f"/api/alerts/{alert_id}/acknowledge",
            headers={"X-API-Key": DEVELOPER_API_KEY}
        )
        assert r_dev_ack.status_code == 403

        # 5. Analyst acknowledge -> 200
        r_ack = await client.post(
            f"/api/alerts/{alert_id}/acknowledge",
            headers={"X-API-Key": ANALYST_API_KEY}
        )
        assert r_ack.status_code == 200
        assert r_ack.json()["status"] == "ACKNOWLEDGED"

        # 6. Admin resolve -> 200
        r_res = await client.post(
            f"/api/alerts/{alert_id}/resolve",
            headers={"X-API-Key": ADMIN_API_KEY}
        )
        assert r_res.status_code == 200
        assert r_res.json()["status"] == "RESOLVED"


@pytest.mark.asyncio
async def test_alert_api_summary_and_open_endpoints():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        headers = {"X-API-Key": ADMIN_API_KEY}

        r_sum = await client.get("/api/alerts/summary", headers=headers)
        assert r_sum.status_code == 200
        data = r_sum.json()
        assert "total_alerts" in data
        assert "open_alerts" in data
        assert "critical_count" in data

        r_open = await client.get("/api/alerts/open", headers=headers)
        assert r_open.status_code == 200
        assert isinstance(r_open.json(), list)
