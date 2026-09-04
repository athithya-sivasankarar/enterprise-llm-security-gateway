import pytest
from fastapi import HTTPException
from backend.security.auth import authenticate_api_key, API_KEYS


@pytest.mark.asyncio
async def test_auth_missing_api_key():
    with pytest.raises(HTTPException) as exc_info:
        await authenticate_api_key(None)
    assert exc_info.value.status_code == 401
    assert "Missing API key" in exc_info.value.detail


@pytest.mark.asyncio
async def test_auth_invalid_api_key():
    with pytest.raises(HTTPException) as exc_info:
        await authenticate_api_key("invalid-secret-key-99999")
    assert exc_info.value.status_code == 401
    assert "Invalid API key" in exc_info.value.detail


@pytest.mark.asyncio
async def test_auth_valid_api_key():
    user = await authenticate_api_key("dev-key-12345")
    assert user is not None
    assert user["user"] == "developer"
    assert user["role"] == "admin"


@pytest.mark.asyncio
async def test_auth_analyst_key():
    user = await authenticate_api_key("test-key-67890")
    assert user is not None
    assert user["user"] == "security-analyst"
    assert user["role"] == "analyst"
