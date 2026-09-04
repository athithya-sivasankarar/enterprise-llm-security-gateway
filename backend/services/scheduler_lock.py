import logging
from typing import Optional
from backend.core.redis_client import redis_client

logger = logging.getLogger(__name__)

LOCK_PREFIX = "security_campaign:lock:"
DEFAULT_LOCK_TTL_SECONDS = 300  # 5 minutes safety timeout


async def acquire_campaign_lock(campaign_id: str, ttl_seconds: int = DEFAULT_LOCK_TTL_SECONDS) -> bool:
    """
    Acquire an atomic distributed lock for campaign execution in Redis.
    Returns True if lock was acquired, False if campaign is already executing.
    """
    if not campaign_id:
        return False

    lock_key = f"{LOCK_PREFIX}{campaign_id}"
    try:
        # SET key value NX EX ttl
        acquired = await redis_client.set(lock_key, "locked", ex=ttl_seconds, nx=True)
        if acquired:
            logger.info(f"Acquired execution lock for campaign '{campaign_id}' (TTL: {ttl_seconds}s)")
            return True
        else:
            logger.warning(f"Failed to acquire lock for campaign '{campaign_id}': execution already in progress")
            return False
    except Exception as e:
        logger.error(f"Redis error while acquiring lock for campaign '{campaign_id}': {e}")
        # Fail safe: do not allow uncoordinated duplicate execution if Redis fails
        return False


async def release_campaign_lock(campaign_id: str) -> None:
    """
    Release the campaign execution distributed lock in Redis.
    """
    if not campaign_id:
        return

    lock_key = f"{LOCK_PREFIX}{campaign_id}"
    try:
        await redis_client.delete(lock_key)
        logger.info(f"Released execution lock for campaign '{campaign_id}'")
    except Exception as e:
        logger.debug(f"Redis error while releasing lock for campaign '{campaign_id}': {e}")
