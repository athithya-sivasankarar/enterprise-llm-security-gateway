import pytest
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient, ASGITransport

from backend.main import app
from backend.security.rbac import is_model_allowed, get_allowed_models_for_role, has_dashboard_access
from backend.providers.base import LLMProvider
from backend.core.redis_client import redis_client

ADMIN_KEY = "dev-key-12345"       # role: admin
ANALYST_KEY = "test-key-67890"     # role: analyst
DEVELOPER_KEY = "dev-user-key-54321" # role: developer


# =============================================================================
# Unit Tests for RBAC Logic
# =============================================================================

def test_rbac_model_authorization_logic():
    # Admin default models
    assert is_model_allowed("admin", "mock-model") is True
    assert is_model_allowed("admin", "gpt-4o-mini") is True
    assert is_model_allowed("admin", "gpt-4") is True
    assert is_model_allowed("admin", "restricted-model") is False

    # Analyst default models
    assert is_model_allowed("analyst", "mock-model") is True
    assert is_model_allowed("analyst", "gpt-4o-mini") is True
    assert is_model_allowed("analyst", "restricted-model") is False

    # Developer default models
    assert is_model_allowed("developer", "mock-model") is True
    assert is_model_allowed("developer", "gpt-4o-mini") is False
    assert is_model_allowed("developer", "restricted-model") is False

    # Empty / Invalid roles
    assert is_model_allowed("", "mock-model") is False
    assert is_model_allowed("unknown-role", "mock-model") is False


def test_rbac_dashboard_permission_logic():
    assert has_dashboard_access("admin") is True
    assert has_dashboard_access("analyst") is True
    assert has_dashboard_access("developer") is False
    assert has_dashboard_access("guest") is False
    assert has_dashboard_access("") is False


# =============================================================================
# API Endpoint Integration Tests (/api/chat RBAC Enforcement)
# =============================================================================

@pytest.mark.asyncio
async def test_chat_allowed_model_for_developer():
    await redis_client.delete(f"rate_limit:{DEVELOPER_KEY}")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/chat",
            headers={"X-API-Key": DEVELOPER_KEY},
            json={"prompt": "Explain TLS", "model": "mock-model"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["security"]["action"] == "ALLOW"


@pytest.mark.asyncio
async def test_chat_unauthorized_model_for_developer_denied_http_403():
    await redis_client.delete(f"rate_limit:{DEVELOPER_KEY}")

    mock_provider = AsyncMock(spec=LLMProvider)

    transport = ASGITransport(app=app)
    with patch("backend.api.chat.get_provider", return_value=mock_provider):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/api/chat",
                headers={"X-API-Key": DEVELOPER_KEY},
                json={"prompt": "Explain TLS", "model": "restricted-model"}
            )
            assert response.status_code == 403
            data = response.json()["detail"]
            assert data["action"] == "BLOCK"
            assert data["threat_type"] == "MODEL_ACCESS_DENIED"
            assert "You are not authorized to use this model" in data["message"]

            # CRITICAL: Provider must NEVER have been called for unauthorized model
            mock_provider.generate.assert_not_called()


@pytest.mark.asyncio
async def test_chat_unauthorized_model_for_analyst_denied_http_403():
    await redis_client.delete(f"rate_limit:{ANALYST_KEY}")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/chat",
            headers={"X-API-Key": ANALYST_KEY},
            json={"prompt": "Explain TLS", "model": "restricted-model"}
        )
        assert response.status_code == 403
        data = response.json()["detail"]
        assert data["threat_type"] == "MODEL_ACCESS_DENIED"


# =============================================================================
# SOC Dashboard RBAC Authorization Tests
# =============================================================================

@pytest.mark.asyncio
async def test_dashboard_admin_access_allowed():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/dashboard/summary",
            headers={"X-API-Key": ADMIN_KEY}
        )
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_dashboard_analyst_access_allowed():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/dashboard/summary",
            headers={"X-API-Key": ANALYST_KEY}
        )
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_dashboard_developer_access_denied_http_403():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/dashboard/summary",
            headers={"X-API-Key": DEVELOPER_KEY}
        )
        assert response.status_code == 403
        assert "Access restricted" in response.json()["detail"]


# =============================================================================
# Permissions & Identity Endpoints Tests (/api/auth/me & /api/rbac/permissions)
# =============================================================================

@pytest.mark.asyncio
async def test_permissions_endpoint_unauthenticated():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/auth/me")
        assert response.status_code == 401


@pytest.mark.asyncio
async def test_permissions_endpoint_for_developer():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/auth/me",
            headers={"X-API-Key": DEVELOPER_KEY}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["user"] == "app-developer"
        assert data["role"] == "developer"
        assert "mock-model" in data["allowed_models"]
        assert data["dashboard_access"] is False

        # Privacy assertion: No secrets or raw API keys in response
        content = str(data)
        assert DEVELOPER_KEY not in content
        assert "password" not in content


@pytest.mark.asyncio
async def test_permissions_endpoint_for_analyst():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/rbac/permissions",
            headers={"X-API-Key": ANALYST_KEY}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["user"] == "security-analyst"
        assert data["role"] == "analyst"
        assert data["dashboard_access"] is True
