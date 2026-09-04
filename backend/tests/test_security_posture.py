import pytest
import httpx
from backend.main import app

ADMIN_API_KEY = "dev-key-12345"
DEVELOPER_API_KEY = "dev-user-key-54321"


@pytest.mark.asyncio
async def test_security_posture_endpoint():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        # Developer access blocked
        r_dev = await client.get(
            "/api/dashboard/security-posture",
            headers={"X-API-Key": DEVELOPER_API_KEY}
        )
        assert r_dev.status_code == 403

        # Admin access allowed
        r_admin = await client.get(
            "/api/dashboard/security-posture",
            headers={"X-API-Key": ADMIN_API_KEY}
        )
        assert r_admin.status_code == 200
        data = r_admin.json()

        # Check required fields
        assert "status" in data
        assert data["status"] in ("SECURE", "DEGRADED", "CRITICAL")
        assert "overall_score" in data
        assert isinstance(data["overall_score"], (int, float))
        assert "previous_score" in data
        assert "score_delta" in data
        assert "active_campaigns" in data
        assert "scheduled_campaigns" in data
        assert "open_alerts" in data
        assert "critical_alerts" in data
        assert "high_alerts" in data
        assert "regressions" in data
        assert "policy_version" in data
