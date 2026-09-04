import pytest
import httpx
from backend.main import app
from backend.db.database import AsyncSessionLocal
from backend.services.incident_service import create_incident
from backend.incidents.models import IncidentCreateRequest

ADMIN_API_KEY = "dev-key-12345"
ANALYST_API_KEY = "test-key-67890"
DEVELOPER_API_KEY = "dev-user-key-54321"


@pytest.mark.asyncio
async def test_incident_api_rbac_rules():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        # Seed an incident
        async with AsyncSessionLocal() as session:
            inc = await create_incident(
                session,
                IncidentCreateRequest(
                    title="RBAC Enforcement Test Incident",
                    description="Validating role restrictions",
                    severity="HIGH"
                ),
                user="admin"
            )
            incident_id = inc.incident_id

        # 1. Unauthenticated -> 401
        r_unauth = await client.get("/api/incidents")
        assert r_unauth.status_code == 401

        # 2. Developer -> 403
        r_dev_list = await client.get("/api/incidents", headers={"X-API-Key": DEVELOPER_API_KEY})
        assert r_dev_list.status_code == 403

        r_dev_create = await client.post(
            "/api/incidents",
            headers={"X-API-Key": DEVELOPER_API_KEY},
            json={"title": "Dev Incident", "description": "Should fail"}
        )
        assert r_dev_create.status_code == 403

        r_dev_detail = await client.get(
            f"/api/incidents/{incident_id}",
            headers={"X-API-Key": DEVELOPER_API_KEY}
        )
        assert r_dev_detail.status_code == 403

        # 3. Analyst -> 200 / 201
        r_analyst_list = await client.get("/api/incidents", headers={"X-API-Key": ANALYST_API_KEY})
        assert r_analyst_list.status_code == 200
        assert isinstance(r_analyst_list.json(), list)

        r_analyst_detail = await client.get(
            f"/api/incidents/{incident_id}",
            headers={"X-API-Key": ANALYST_API_KEY}
        )
        assert r_analyst_detail.status_code == 200
        assert r_analyst_detail.json()["incident"]["incident_id"] == incident_id

        # 4. Admin -> 200 / 201
        r_admin_summary = await client.get("/api/incidents/summary", headers={"X-API-Key": ADMIN_API_KEY})
        assert r_admin_summary.status_code == 200
        assert "total_incidents" in r_admin_summary.json()
