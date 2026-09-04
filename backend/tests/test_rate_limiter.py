import pytest
from unittest.mock import AsyncMock, patch
from fastapi import HTTPException
from redis.exceptions import ConnectionError as RedisConnectionError
from backend.security.rate_limiter import check_rate_limit, REQUEST_LIMIT
from backend.core.redis_client import redis_client


@pytest.mark.asyncio
async def test_rate_limiter_allows_under_limit():
    test_key = "unit-test-key-allow"
    # Clear key first
    await redis_client.delete(f"rate_limit:{test_key}")

    # 10 requests should succeed
    for _ in range(REQUEST_LIMIT):
        allowed = await check_rate_limit(test_key)
        assert allowed is True

    # Clean up
    await redis_client.delete(f"rate_limit:{test_key}")


@pytest.mark.asyncio
async def test_rate_limiter_blocks_over_limit():
    test_key = "unit-test-key-block"
    await redis_client.delete(f"rate_limit:{test_key}")

    # Exhaust limit
    for _ in range(REQUEST_LIMIT):
        await check_rate_limit(test_key)

    # 11th request must raise HTTP 429
    with pytest.raises(HTTPException) as exc_info:
        await check_rate_limit(test_key)

    assert exc_info.value.status_code == 429
    assert "Rate limit exceeded" in exc_info.value.detail

    # Clean up
    await redis_client.delete(f"rate_limit:{test_key}")


@pytest.mark.asyncio
async def test_rate_limiter_key_expiration():
    test_key = "unit-test-key-ttl"
    await redis_client.delete(f"rate_limit:{test_key}")

    await check_rate_limit(test_key)
    ttl = await redis_client.ttl(f"rate_limit:{test_key}")
    assert 0 < ttl <= 60

    # Clean up
    await redis_client.delete(f"rate_limit:{test_key}")


@pytest.mark.asyncio
async def test_rate_limiter_fails_safely_on_redis_error():
    test_key = "unit-test-redis-fail"
    with patch.object(redis_client, "incr", side_effect=RedisConnectionError("Redis connection lost")):
        with pytest.raises(HTTPException) as exc_info:
            await check_rate_limit(test_key)
        assert exc_info.value.status_code == 503
        assert "temporarily unavailable" in exc_info.value.detail
