"""IronGate -- Redis Connection Manager.

Provides cache, pub/sub, and rate limiting services backed by Redis.
All services degrade gracefully if Redis is unavailable -- operations
become no-ops rather than crashing the application.
"""
import json
import logging
from typing import Any, Optional

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

_redis_client = None
_redis_available = False


def _get_redis_client():
    """Lazy-initialize the Redis connection pool.

    Called on first use rather than at import time so the application
    can start even if Redis is temporarily unreachable.
    """
    global _redis_client, _redis_available
    if _redis_client is not None:
        return _redis_client

    try:
        import redis.asyncio as aioredis
        pool = aioredis.ConnectionPool.from_url(
            settings.REDIS_URL,
            max_connections=settings.REDIS_MAX_CONNECTIONS,
            decode_responses=True,
        )
        _redis_client = aioredis.Redis(connection_pool=pool)
        _redis_available = True
        return _redis_client
    except Exception as e:
        logger.warning("Redis connection pool creation failed: %s", e)
        _redis_available = False
        return None


async def _check_redis() -> bool:
    """Check if Redis is reachable, updating the availability flag."""
    global _redis_available
    client = _get_redis_client()
    if client is None:
        _redis_available = False
        return False
    try:
        await client.ping()
        _redis_available = True
        return True
    except Exception:
        _redis_available = False
        return False


class CacheService:
    """Key-value cache backed by Redis. Falls back to no-ops when Redis is down."""

    def __init__(self):
        self.default_ttl = settings.REDIS_CACHE_TTL

    async def get(self, key: str) -> Optional[Any]:
        client = _get_redis_client()
        if client is None:
            return None
        try:
            val = await client.get(f"cache:{key}")
            if val:
                try:
                    return json.loads(val)
                except (json.JSONDecodeError, TypeError):
                    return val
        except Exception as e:
            logger.debug("Cache get failed for %s: %s", key, e)
        return None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None):
        client = _get_redis_client()
        if client is None:
            return
        try:
            s = json.dumps(value) if not isinstance(value, str) else value
            await client.set(f"cache:{key}", s, ex=ttl or self.default_ttl)
        except Exception as e:
            logger.debug("Cache set failed for %s: %s", key, e)

    async def delete(self, key: str):
        client = _get_redis_client()
        if client is None:
            return
        try:
            await client.delete(f"cache:{key}")
        except Exception as e:
            logger.debug("Cache delete failed for %s: %s", key, e)

    async def invalidate_pattern(self, pattern: str) -> int:
        client = _get_redis_client()
        if client is None:
            return 0
        count = 0
        try:
            async for key in client.scan_iter(f"cache:{pattern}"):
                await client.delete(key)
                count += 1
        except Exception as e:
            logger.debug("Cache invalidate_pattern failed for %s: %s", pattern, e)
        return count


class PubSubService:
    """Redis Pub/Sub for real-time event broadcasting. No-ops when Redis is down."""

    CHANNELS = {
        "threats": "irongate:threats",
        "bans": "irongate:bans",
        "agents": "irongate:agents",
        "trust": "irongate:trust",
    }

    async def publish(self, channel: str, data: dict):
        client = _get_redis_client()
        if client is None:
            return 0
        ch = self.CHANNELS.get(channel, f"irongate:{channel}")
        try:
            return await client.publish(ch, json.dumps(data))
        except Exception as e:
            logger.debug("PubSub publish failed for %s: %s", channel, e)
            return 0

    async def subscribe(self, channel: str):
        client = _get_redis_client()
        if client is None:
            raise RuntimeError("Redis is not available for pub/sub subscriptions")
        ch = self.CHANNELS.get(channel, f"irongate:{channel}")
        pubsub = client.pubsub()
        await pubsub.subscribe(ch)
        return pubsub


class RateLimitService:
    """Token-bucket rate limiter backed by Redis atomic increments."""

    async def check_rate_limit(
        self, key: str, max_requests: int, window_seconds: int,
    ) -> tuple[bool, int]:
        """Check and increment rate limit counter.

        Returns (allowed: bool, remaining: int).
        Falls back to allowing all requests when Redis is unavailable.
        """
        client = _get_redis_client()
        if client is None:
            return True, max_requests

        try:
            full_key = f"ratelimit:{key}"
            pipe = client.pipeline()
            pipe.incr(full_key)
            pipe.ttl(full_key)
            results = await pipe.execute()

            current_count = results[0]
            current_ttl = results[1]

            if current_ttl == -1:
                await client.expire(full_key, window_seconds)

            remaining = max(0, max_requests - current_count)
            return current_count <= max_requests, remaining
        except Exception as e:
            logger.debug("Rate limit check failed for %s: %s", key, e)
            return True, max_requests


# Module-level service instances (lazy -- no Redis connection until first call)
cache_service = CacheService()
pubsub_service = PubSubService()
rate_limit_service = RateLimitService()


# For backwards compatibility: provide a redis_client property that
# initializes lazily. Used by main.py health check and lifespan.
class _LazyRedisClient:
    """Proxy that defers Redis connection until first attribute access."""

    def __getattr__(self, name):
        client = _get_redis_client()
        if client is None:
            raise RuntimeError("Redis is not available")
        return getattr(client, name)


redis_client = _LazyRedisClient()
