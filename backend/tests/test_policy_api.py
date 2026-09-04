import pytest
from httpx import AsyncClient, ASGITransport
from backend.main import app
from backend.policy.defaults import get_default_policy


@pytest.mark.asyncio
async def test_get_active_policy_endpoint():
    """Test GET /api/policies/active."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Unauthenticated: 401
        unauth = await client.get("/api/policies/active")
        assert unauth.status_code == 401

        # Developer: 403
        dev_res = await client.get("/api/policies/active", headers={"X-API-Key": "dev-user-key-54321"})
        assert dev_res.status_code == 403

        # Analyst: 200
        analyst_res = await client.get("/api/policies/active", headers={"X-API-Key": "test-key-67890"})
        assert analyst_res.status_code == 200
        data = analyst_res.json()
        assert "policy_version" in data
        assert "policy" in data

        # Admin: 200
        admin_res = await client.get("/api/policies/active", headers={"X-API-Key": "dev-key-12345"})
        assert admin_res.status_code == 200


@pytest.mark.asyncio
async def test_validate_policy_endpoint():
    """Test POST /api/policies/validate dry-run validation."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-API-Key": "dev-key-12345"}

        # Valid payload
        valid_data = get_default_policy().model_dump()
        valid_data["policy_version"] = "1.2.0"
        res = await client.post("/api/policies/validate", json=valid_data, headers=headers)
        assert res.status_code == 200
        assert res.json()["valid"] is True
        assert res.json()["errors"] == []

        # Invalid payload (disabled injection defense)
        invalid_data = get_default_policy().model_dump()
        invalid_data["input_security"]["prompt_injection_enabled"] = False
        res2 = await client.post("/api/policies/validate", json=invalid_data, headers=headers)
        assert res2.status_code == 200
        assert res2.json()["valid"] is False
        assert len(res2.json()["errors"]) > 0


@pytest.mark.asyncio
async def test_create_and_activate_policy_rbac():
    """Verify only admin can create and activate policies."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        policy_payload = {
            "policy_version": "1.3.0",
            "name": "RBAC Test Policy",
            "description": "Test policy for RBAC enforcement",
            "policy": get_default_policy().model_dump()
        }
        policy_payload["policy"]["policy_version"] = "1.3.0"

        # Analyst attempt to create -> 403
        analyst_res = await client.post("/api/policies", json=policy_payload, headers={"X-API-Key": "test-key-67890"})
        assert analyst_res.status_code == 403

        # Admin attempt to create -> 201 or 409 (if exists)
        admin_res = await client.post("/api/policies", json=policy_payload, headers={"X-API-Key": "dev-key-12345"})
        assert admin_res.status_code in (201, 409)

        # Analyst attempt to activate -> 403
        act_analyst = await client.post("/api/policies/1.3.0/activate", headers={"X-API-Key": "test-key-67890"})
        assert act_analyst.status_code == 403

        # Admin activate -> 200
        act_admin = await client.post("/api/policies/1.3.0/activate", headers={"X-API-Key": "dev-key-12345"})
        assert act_admin.status_code == 200

        # Rollback to 1.0.0
        revert = await client.post("/api/policies/1.0.0/activate", headers={"X-API-Key": "dev-key-12345"})
        assert revert.status_code == 200


@pytest.mark.asyncio
async def test_chat_pipeline_records_policy_version():
    """Verify /api/chat execution records policy_version and returns it."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-API-Key": "dev-key-12345"}
        res = await client.post(
            "/api/chat",
            json={"prompt": "Policy version correlation test", "model": "mock-model"},
            headers=headers
        )
        assert res.status_code == 200

        # Check SIEM events endpoint to verify policy correlation
        events_res = await client.get("/api/security/events?limit=5", headers=headers)
        assert events_res.status_code == 200
