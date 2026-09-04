import os
import asyncio
from typing import Dict
import redis.asyncio as redis

REDIS_URL = os.getenv("REDIS_URL")
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))


class RedisClientProxy:
    """
    Proxy for Redis client that lazily instantiates and manages the Redis
    client per asyncio event loop (preventing loop-attachment errors in pytest and async workers).
    Supports either REDIS_URL or host/port configuration.
    """
    def __init__(self, host: str = REDIS_HOST, port: int = REDIS_PORT, db: int = 0, url: str | None = REDIS_URL):
        self.host = host
        self.port = port
        self.db = db
        self.url = url
        self._clients: Dict[int, redis.Redis] = {}

    def _get_client(self) -> redis.Redis:
        try:
            loop = asyncio.get_running_loop()
            loop_id = id(loop)
        except RuntimeError:
            loop_id = 0

        if loop_id not in self._clients:
            if self.url or os.getenv("REDIS_URL"):
                effective_url = self.url or os.getenv("REDIS_URL")
                self._clients[loop_id] = redis.from_url(
                    effective_url,
                    decode_responses=True
                )
            else:
                effective_host = os.getenv("REDIS_HOST", self.host)
                effective_port = int(os.getenv("REDIS_PORT", self.port))
                self._clients[loop_id] = redis.Redis(
                    host=effective_host,
                    port=effective_port,
                    db=self.db,
                    decode_responses=True
                )
        return self._clients[loop_id]

    def __getattr__(self, name):
        return getattr(self._get_client(), name)


redis_client = RedisClientProxy()


async def check_redis_connection() -> bool:
    try:
        return await redis_client.ping()
    except Exception:
        return False
