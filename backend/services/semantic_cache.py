import os
import re
import json
import time
import hashlib
import logging
import unicodedata
from typing import Optional

from backend.core.redis_client import redis_client

logger = logging.getLogger(__name__)

CACHE_NAMESPACE_PREFIX = "llm_cache:v1"
DEFAULT_CACHE_TTL = int(os.getenv("SEMANTIC_CACHE_TTL_SECONDS", "300"))


def is_cache_enabled() -> bool:
    """
    Check whether semantic caching is enabled via environment configuration.
    """
    val = os.getenv("SEMANTIC_CACHE_ENABLED", "true").lower()
    return val in ("true", "1", "yes", "on")


def normalize_prompt(prompt: str) -> str:
    """
    Lightweight semantic prompt normalization.
    Performs NFKC unicode normalization, lowercasing, canonical punctuation stripping,
    and multiple-whitespace collapse.
    
    Ensures 'Explain TLS.' and '  explain   tls  ' produce identical representations,
    while maintaining semantic distinction across different topics.
    """
    if not prompt:
        return ""

    # 1. Unicode NFKC normalization
    text = unicodedata.normalize("NFKC", prompt)

    # 2. Lowercase
    text = text.lower()

    # 3. Strip surrounding trailing/leading punctuation (periods, question marks, exclamation marks)
    text = re.sub(r"^[^\w]+|[^\w]+$", "", text)

    # 4. Collapse consecutive whitespace (spaces, tabs, newlines) into a single space
    text = re.sub(r"\s+", " ", text).strip()

    return text


def generate_cache_key(prompt: str, model: str, role: str, provider: str = "default") -> str:
    """
    Generate a deterministic, role-isolated, and model-isolated SHA-256 cache key.
    Format: llm_cache:v1:<provider>:<role>:<model>:<sha256(normalized_prompt)>
    """
    normalized = normalize_prompt(prompt)
    prompt_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    
    clean_provider = (provider or "default").lower().strip()
    clean_role = (role or "unknown").lower().strip()
    clean_model = (model or "default").lower().strip()

    return f"{CACHE_NAMESPACE_PREFIX}:{clean_provider}:{clean_role}:{clean_model}:{prompt_hash}"


async def get_cached_response(
    prompt: str,
    model: str,
    user_role: str,
    provider: str = "default"
) -> Optional[str]:
    """
    Retrieve cached LLM completion for a normalized sanitized prompt.
    Fails safely if Redis is unreachable without raising exceptions.
    """
    if not is_cache_enabled():
        return None

    key = generate_cache_key(prompt, model, user_role, provider)

    try:
        raw_val = await redis_client.get(key)
        if not raw_val:
            return None

        # Parse stored payload
        data = json.loads(raw_val)
        cached_response = data.get("response")

        logger.info(
            "Semantic Cache HIT: key=%s, model=%s, role=%s",
            key,
            model,
            user_role
        )
        return cached_response
    except Exception as exc:
        logger.warning("Semantic cache lookup failed safely (bypassing cache): %s", exc)
        return None


async def cache_response(
    prompt: str,
    model: str,
    user_role: str,
    response: str,
    provider: str = "default",
    ttl: Optional[int] = None
) -> bool:
    """
    Cache an approved and sanitized LLM response.
    Never caches raw PII or secret credentials.
    """
    if not is_cache_enabled() or not response:
        return False

    key = generate_cache_key(prompt, model, user_role, provider)
    effective_ttl = ttl if ttl is not None else DEFAULT_CACHE_TTL

    payload = {
        "response": response,
        "model": model,
        "role": user_role,
        "provider": provider,
        "cached_at": time.time()
    }

    try:
        await redis_client.set(
            key,
            json.dumps(payload),
            ex=effective_ttl
        )
        logger.info(
            "Semantic Cache WRITE: key=%s, model=%s, role=%s, ttl=%ds",
            key,
            model,
            user_role,
            effective_ttl
        )
        return True
    except Exception as exc:
        logger.warning("Semantic cache write failed safely: %s", exc)
        return False


async def clear_cache() -> int:
    """
    Clear all semantic cache entries in Redis without touching rate_limit:* keys.
    """
    deleted_count = 0
    try:
        cursor = 0
        keys_to_delete = []
        
        # Scan for llm_cache:v1:* keys safely using Redis client
        while True:
            cursor, keys = await redis_client.scan(cursor=cursor, match=f"{CACHE_NAMESPACE_PREFIX}:*", count=100)
            if keys:
                keys_to_delete.extend(keys)
            if cursor == 0:
                break

        if keys_to_delete:
            deleted_count = await redis_client.delete(*keys_to_delete)

        logger.info("Cleared %d semantic cache keys from Redis", deleted_count)
        return deleted_count
    except Exception as exc:
        logger.error("Failed to clear semantic cache: %s", exc)
        return 0
