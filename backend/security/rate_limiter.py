import logging
from fastapi import HTTPException, status
from redis.exceptions import RedisError
from backend.core.redis_client import redis_client
from backend.observability.metrics import record_rate_limit_blocked
from backend.observability.tracing import trace_span

logger = logging.getLogger(__name__)

DEFAULT_REQUEST_LIMIT = 10
DEFAULT_WINDOW_SECONDS = 60
REQUEST_LIMIT = DEFAULT_REQUEST_LIMIT
WINDOW_SECONDS = DEFAULT_WINDOW_SECONDS


async def check_rate_limit(
    api_key: str,
    role: str | None = None,
    limit: int = DEFAULT_REQUEST_LIMIT,
    window_seconds: int = DEFAULT_WINDOW_SECONDS
) -> bool:
    """
    Enforce rate limits per API key using Redis counter and expiration.
    Uses dynamic limits from active security policy (defaults to 10 req/60s).
    Fails safely if Redis is unavailable.
    """
    with trace_span("security.rate_limit", {"limit": limit, "window_s": window_seconds}):
        if not api_key:
            api_key = "anonymous"

        redis_key = f"rate_limit:{api_key}"

        try:
            current_count = await redis_client.incr(redis_key)

            if current_count == 1:
                await redis_client.expire(
                    redis_key,
                    window_seconds
                )
        except (RedisError, ConnectionError, OSError) as exc:
            logger.error(f"Redis rate limiter error: {exc}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Rate limiting service is temporarily unavailable"
            ) from exc

        if current_count > limit:
            record_rate_limit_blocked(role=role)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Try again later."
            )

        return True
