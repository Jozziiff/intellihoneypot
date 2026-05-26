"""
LLM response cache.

Why cache? Each LLM call has latency (200 ms–3 s) and may cost money.
Attackers tend to type the same command many times (`ls`, `whoami`, `uname -a`),
so caching turns those into ~1 ms Redis reads.

Cache key strategy:
    SHA-256( "<command>::<last 3 commands>" )

We include the recent history in the key so that `ls` after `cd /etc`
gets a different answer than `ls` after `cd /home/admin`.
"""
from __future__ import annotations

import hashlib

from redis.asyncio import Redis

from app.core.logging import get_logger

logger = get_logger(__name__)

_CACHE_PREFIX = "llm:cache:"


class ResponseCache:
    def __init__(self, redis: Redis, ttl: int = 3600) -> None:
        self._redis = redis
        self._ttl = ttl

    def _make_key(self, command: str, context: str) -> str:
        # Strip then concatenate so trivial whitespace doesn't fragment the cache.
        raw = f"{command.strip()}::{context.strip()}"
        digest = hashlib.sha256(raw.encode()).hexdigest()
        return f"{_CACHE_PREFIX}{digest}"

    async def get(self, command: str, context: str) -> str | None:
        key = self._make_key(command, context)
        value = await self._redis.get(key)
        if value is not None:
            logger.debug("cache_hit", key=key[:20])
        return value  # type: ignore[return-value]

    async def set(self, command: str, context: str, response: str) -> None:
        key = self._make_key(command, context)
        await self._redis.setex(key, self._ttl, response)
        logger.debug("cache_set", key=key[:20])

    async def invalidate(self, command: str, context: str) -> None:
        key = self._make_key(command, context)
        await self._redis.delete(key)

    async def flush_all(self) -> int:
        """Wipe every cache entry. Returns how many keys were deleted."""
        keys = await self._redis.keys(f"{_CACHE_PREFIX}*")
        if keys:
            return await self._redis.delete(*keys)
        return 0
