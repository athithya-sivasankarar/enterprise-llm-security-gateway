import pytest
import httpx
from datetime import datetime, timezone, timedelta
from backend.main import app

ADMIN_API_KEY = "dev-key-12345"
ANALYST_API_KEY = "test-key-67890"
DEVELOPER_API_KEY = "dev-user-key-54321"


@pytest.mark.asyncio
async def test_governance_rbac_enforcement():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        endpoints = [
            ("GET", "/api/governance/summary"),
            ("GET", "/api/governance/risk"),
            ("GET", "/api/governance/controls"),
            ("GET", "/api/governance/exceptions"),
            ("GET", "/api/governance/exceptions/overdue"),
            ("GET", "/api/governance/reviews"),
            ("GET", "/api/governance/assurance"),
            ("GET", "/api/governance/events"),
        ]

        # 1. Developer Role MUST receive HTTP 403 Forbidden
        dev_headers = {"X-API-Key": DEVELOPER_API_KEY}
        for method, ep in endpoints:
            if method == "GET":
                res = await client.get(ep, headers=dev_headers)
                assert res.status_code == 403, f"Expected 403 for developer on {ep}, got {res.status_code}"

        # 2. Unauthenticated requests MUST receive HTTP 401 Unauthorized
        for method, ep in endpoints:
            if method == "GET":
                res = await client.get(ep)
                assert res.status_code == 401, f"Expected 401 for unauthenticated on {ep}, got {res.status_code}"

        # 3. Admin and Analyst MUST be allowed (HTTP 200)
        admin_headers = {"X-API-Key": ADMIN_API_KEY}
        analyst_headers = {"X-API-Key": ANALYST_API_KEY}

        for method, ep in endpoints:
            res_admin = await client.get(ep, headers=admin_headers)
            assert res_admin.status_code == 200, f"Expected 200 for admin on {ep}, got {res_admin.status_code}"

            res_analyst = await client.get(ep, headers=analyst_headers)
            assert res_analyst.status_code == 200, f"Expected 200 for analyst on {ep}, got {res_analyst.status_code}"
