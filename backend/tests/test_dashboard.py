import uuid
import pytest
from httpx import AsyncClient, ASGITransport
from backend.main import app
from backend.services.audit import record_audit_log
from backend.db.database import AsyncSessionLocal
from backend.db.models import AuditLog

DEV_API_KEY = "dev-key-12345"
ANALYST_API_KEY = "test-key-67890"
INVALID_API_KEY = "invalid-key-99999"


# =============================================================================
# Dashboard Authentication Tests
# =============================================================================

@pytest.mark.asyncio
async def test_dashboard_missing_auth():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/dashboard/summary")
        assert response.status_code == 401
        assert "Missing API key" in response.json()["detail"]


@pytest.mark.asyncio
async def test_dashboard_invalid_auth():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/dashboard/summary",
            headers={"X-API-Key": INVALID_API_KEY}
        )
        assert response.status_code == 401
        assert "Invalid API key" in response.json()["detail"]


# =============================================================================
# Dashboard Analytics Endpoints Tests
# =============================================================================

@pytest.mark.asyncio
async def test_dashboard_summary_endpoint():
    # Insert test audit records
    req1 = str(uuid.uuid4())
    req2 = str(uuid.uuid4())

    await record_audit_log(
        request_id=req1,
        user="test_dev",
        role="admin",
        model="mock-model",
        action="ALLOW",
        risk_score=0,
        pii_detected=False,
        injection_detected=False,
        threat_type=None,
        response_status=200,
        latency_ms=15.0
    )
    await record_audit_log(
        request_id=req2,
        user="test_analyst",
        role="analyst",
        model="gpt-4o-mini",
        action="BLOCK",
        risk_score=95,
        pii_detected=True,
        injection_detected=True,
        threat_type="INSTRUCTION_OVERRIDE",
        response_status=403,
        latency_ms=25.0,
        detected_entities=["EMAIL_ADDRESS"],
        response_action="BLOCK",
        response_threat_type="UNSAFE_CONTENT"
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/dashboard/summary",
            headers={"X-API-Key": DEV_API_KEY}
        )
        assert response.status_code == 200
        data = response.json()

        assert "total_requests" in data
        assert "allowed" in data
        assert "blocked" in data
        assert "sanitized" in data
        assert "pii_detections" in data
        assert "injection_detections" in data
        assert "response_blocks" in data
        assert "average_latency_ms" in data
        assert data["total_requests"] >= 2
        assert data["average_latency_ms"] >= 0


@pytest.mark.asyncio
async def test_dashboard_threats_endpoint():
    req_id = str(uuid.uuid4())
    await record_audit_log(
        request_id=req_id,
        user="test_attacker",
        role="analyst",
        model="mock-model",
        action="BLOCK",
        risk_score=90,
        pii_detected=False,
        injection_detected=True,
        threat_type="JAILBREAK",
        response_status=403,
        latency_ms=10.0
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/dashboard/threats",
            headers={"X-API-Key": DEV_API_KEY}
        )
        assert response.status_code == 200
        data = response.json()
        assert "threats" in data
        assert isinstance(data["threats"], list)
        
        # Verify JAILBREAK threat is included in distribution
        types = [t["type"] for t in data["threats"]]
        assert "JAILBREAK" in types


@pytest.mark.asyncio
async def test_dashboard_recent_events_endpoint():
    req_id = str(uuid.uuid4())
    await record_audit_log(
        request_id=req_id,
        user="test_user_recent",
        role="admin",
        model="mock-model",
        action="SANITIZE",
        risk_score=20,
        pii_detected=True,
        injection_detected=False,
        threat_type=None,
        response_status=200,
        latency_ms=18.5,
        detected_entities=["PHONE_NUMBER"]
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/dashboard/recent-events?limit=10",
            headers={"X-API-Key": DEV_API_KEY}
        )
        assert response.status_code == 200
        data = response.json()
        assert "events" in data
        assert len(data["events"]) > 0

        first_event = data["events"][0]
        assert "request_id" in first_event
        assert "timestamp" in first_event
        assert "user" in first_event
        assert "role" in first_event
        assert "model" in first_event
        assert "action" in first_event
        assert "risk_score" in first_event
        assert "latency_ms" in first_event


@pytest.mark.asyncio
async def test_dashboard_model_analytics():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/dashboard/models",
            headers={"X-API-Key": DEV_API_KEY}
        )
        assert response.status_code == 200
        data = response.json()
        assert "models" in data
        assert isinstance(data["models"], list)


@pytest.mark.asyncio
async def test_dashboard_user_analytics():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/dashboard/users",
            headers={"X-API-Key": DEV_API_KEY}
        )
        assert response.status_code == 200
        data = response.json()
        assert "users" in data
        assert isinstance(data["users"], list)


@pytest.mark.asyncio
async def test_dashboard_timeline_analytics():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/dashboard/timeline",
            headers={"X-API-Key": DEV_API_KEY}
        )
        assert response.status_code == 200
        data = response.json()
        assert "timeline" in data
        assert isinstance(data["timeline"], list)


# =============================================================================
# Dashboard Privacy Verification Tests
# =============================================================================

@pytest.mark.asyncio
async def test_dashboard_privacy_no_raw_pii_or_keys_exposed():
    """
    CRITICAL PRIVACY TEST: Ensure dashboard endpoints do not return raw emails,
    API keys, or raw user prompts.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for endpoint in [
            "/api/dashboard/summary",
            "/api/dashboard/threats",
            "/api/dashboard/recent-events",
            "/api/dashboard/models",
            "/api/dashboard/users",
            "/api/dashboard/timeline"
        ]:
            response = await client.get(endpoint, headers={"X-API-Key": DEV_API_KEY})
            assert response.status_code == 200
            content = str(response.json())

            # Never expose sensitive test values or credentials
            assert "fake.user@example.com" not in content
            assert "dev-key-12345" not in content
            assert "test-key-67890" not in content
            assert "raw_prompt" not in content
            assert "raw_response" not in content
