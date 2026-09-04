import pytest
from httpx import AsyncClient, ASGITransport
from backend.main import app


@pytest.mark.asyncio
async def test_siem_events_authentication_required():
    """Test that /api/security/events rejects unauthenticated requests with HTTP 401."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/security/events")
        assert res.status_code == 401


@pytest.mark.asyncio
async def test_siem_events_rbac_enforcement():
    """Verify that developers are forbidden (HTTP 403) while admin and analyst roles are allowed."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Developer role: Denied
        dev_res = await client.get("/api/security/events", headers={"X-API-Key": "dev-user-key-54321"})
        assert dev_res.status_code == 403

        # Analyst role: Allowed
        analyst_res = await client.get("/api/security/events", headers={"X-API-Key": "test-key-67890"})
        assert analyst_res.status_code == 200

        # Admin role: Allowed
        admin_res = await client.get("/api/security/events", headers={"X-API-Key": "dev-key-12345"})
        assert admin_res.status_code == 200


@pytest.mark.asyncio
async def test_siem_events_normalized_structure_and_privacy():
    """Verify that returned SIEM events conform to standard schema without leaking prompts or secrets."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-API-Key": "dev-key-12345"}
        
        # Trigger an audit event first
        await client.post("/api/chat", json={"prompt": "SIEM audit test", "model": "mock-model"}, headers=headers)

        res = await client.get("/api/security/events?limit=10", headers=headers)
        assert res.status_code == 200
        data = res.json()

        assert "events" in data
        assert "total" in data
        assert isinstance(data["events"], list)

        if data["events"]:
            event = data["events"][0]
            # Required SIEM fields
            assert "event_id" in event
            assert "timestamp" in event
            assert "request_id" in event
            assert "event_type" in event
            assert "severity" in event
            assert "user" in event
            assert "role" in event
            assert "model" in event
            assert "provider" in event
            assert "action" in event
            assert "risk_score" in event
            assert "response_status" in event

            # Strict privacy check: No prompt or response content in event objects
            assert "prompt" not in event
            assert "raw_prompt" not in event
            assert "response" not in event
            assert "raw_response" not in event
            assert "api_key" not in event


@pytest.mark.asyncio
async def test_dashboard_observability_endpoint():
    """Verify /api/dashboard/observability returns required operational metrics and P95 latency."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-API-Key": "dev-key-12345"}
        res = await client.get("/api/dashboard/observability", headers=headers)
        assert res.status_code == 200
        data = res.json()

        # Validate all required telemetry fields
        assert "requests_per_minute" in data
        assert "error_rate" in data
        assert "blocked_requests" in data
        assert "pii_detections" in data
        assert "prompt_injections" in data
        assert "response_blocks" in data
        assert "provider_errors" in data
        assert "cache_hit_rate" in data
        assert "average_latency_ms" in data
        assert "p95_latency_ms" in data

        # Values should be valid numeric types
        assert isinstance(data["error_rate"], (int, float))
        assert isinstance(data["p95_latency_ms"], (int, float))
        assert isinstance(data["blocked_requests"], int)
