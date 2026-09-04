import pytest
from httpx import AsyncClient, ASGITransport
from backend.main import app
from backend.core.redis_client import redis_client

VALID_API_KEY = "dev-key-12345"
ANALYST_API_KEY = "test-key-67890"
INVALID_API_KEY = "invalid-key-99999"


@pytest.mark.asyncio
async def test_root_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/")
        assert response.status_code == 200
        assert response.json()["status"] == "online"


@pytest.mark.asyncio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"


@pytest.mark.asyncio
async def test_chat_missing_api_key():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/chat",
            json={"prompt": "Hello world"}
        )
        assert response.status_code == 401
        assert "Missing API key" in response.json()["detail"]


@pytest.mark.asyncio
async def test_chat_invalid_api_key():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/chat",
            headers={"X-API-Key": INVALID_API_KEY},
            json={"prompt": "Hello world"}
        )
        assert response.status_code == 401
        assert "Invalid API key" in response.json()["detail"]


@pytest.mark.asyncio
async def test_chat_empty_prompt():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/chat",
            headers={"X-API-Key": VALID_API_KEY},
            json={"prompt": ""}
        )
        assert response.status_code == 422


@pytest.mark.asyncio
async def test_chat_normal_prompt_success():
    # Clear rate limit key for clean test
    await redis_client.delete(f"rate_limit:{VALID_API_KEY}")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {"prompt": "Explain SQL injection in simple terms"}
        response = await client.post(
            "/api/chat",
            headers={"X-API-Key": VALID_API_KEY},
            json=payload
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["model"] == "mock-model"
        assert "Mock LLM received: Explain SQL injection in simple terms" in data["response"]
        assert data["security"]["pii_detected"] is False
        assert data["security"]["action"] == "ALLOW"
        assert data["security"]["risk_score"] == 0


@pytest.mark.asyncio
async def test_chat_pii_email_sanitization():
    await redis_client.delete(f"rate_limit:{VALID_API_KEY}")

    raw_email = "fake.user@example.com"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/chat",
            headers={"X-API-Key": VALID_API_KEY},
            json={"prompt": f"My email is {raw_email}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["security"]["pii_detected"] is True
        assert data["security"]["action"] == "SANITIZE"
        assert "<EMAIL_ADDRESS>" in data["response"]
        # Crucial security assertion: original PII is NOT in the mock LLM response
        assert raw_email not in data["response"]


@pytest.mark.asyncio
async def test_chat_pii_phone_sanitization():
    await redis_client.delete(f"rate_limit:{VALID_API_KEY}")

    raw_phone = "+1 555-123-4567"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/chat",
            headers={"X-API-Key": VALID_API_KEY},
            json={"prompt": f"Call me at {raw_phone}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["security"]["pii_detected"] is True
        assert data["security"]["action"] == "SANITIZE"
        assert "<PHONE_NUMBER>" in data["response"]
        assert raw_phone not in data["response"]


@pytest.mark.asyncio
async def test_chat_pii_credit_card_sanitization():
    await redis_client.delete(f"rate_limit:{VALID_API_KEY}")

    raw_card = "4012888888881881"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/chat",
            headers={"X-API-Key": VALID_API_KEY},
            json={"prompt": f"Charge card {raw_card}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["security"]["pii_detected"] is True
        assert data["security"]["action"] == "SANITIZE"
        assert "<CREDIT_CARD>" in data["response"]
        assert raw_card not in data["response"]


@pytest.mark.asyncio
async def test_chat_pii_ssn_sanitization():
    await redis_client.delete(f"rate_limit:{VALID_API_KEY}")

    raw_ssn = "219-09-5432"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/chat",
            headers={"X-API-Key": VALID_API_KEY},
            json={"prompt": f"SSN: {raw_ssn}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["security"]["pii_detected"] is True
        assert data["security"]["action"] == "SANITIZE"
        assert "<US_SSN>" in data["response"]
        assert raw_ssn not in data["response"]


@pytest.mark.asyncio
async def test_chat_rate_limiting_enforcement():
    rate_test_key = "test-key-67890"
    await redis_client.delete(f"rate_limit:{rate_test_key}")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # First 10 requests should succeed
        for i in range(10):
            response = await client.post(
                "/api/chat",
                headers={"X-API-Key": rate_test_key},
                json={"prompt": f"Request number {i+1}"}
            )
            assert response.status_code == 200, f"Request {i+1} failed with {response.status_code}"

        # 11th request must receive HTTP 429
        response_11 = await client.post(
            "/api/chat",
            headers={"X-API-Key": rate_test_key},
            json={"prompt": "Request number 11"}
        )
        assert response_11.status_code == 429
        assert "Rate limit exceeded" in response_11.json()["detail"]

    # Clean up
    await redis_client.delete(f"rate_limit:{rate_test_key}")
