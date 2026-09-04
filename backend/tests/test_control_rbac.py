import pytest
import httpx
from backend.main import app

ADMIN_API_KEY = "dev-key-12345"
ANALYST_API_KEY = "test-key-67890"
DEVELOPER_API_KEY = "dev-user-key-54321"


@pytest.mark.asyncio
async def test_control_rbac():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        # 1. Unauthenticated -> 401
        r_unauth = await client.get("/api/controls")
        assert r_unauth.status_code == 401

        # 2. Developer -> 403
        r_dev = await client.get("/api/controls", headers={"X-API-Key": DEVELOPER_API_KEY})
        assert r_dev.status_code == 403

        r_dev_cov = await client.get("/api/controls/coverage", headers={"X-API-Key": DEVELOPER_API_KEY})
        assert r_dev_cov.status_code == 403

        # 3. Analyst -> 200
        r_analyst = await client.get("/api/controls", headers={"X-API-Key": ANALYST_API_KEY})
        assert r_analyst.status_code == 200

        # 4. Admin -> 200
        r_admin = await client.get("/api/controls/coverage", headers={"X-API-Key": ADMIN_API_KEY})
        assert r_admin.status_code == 200
