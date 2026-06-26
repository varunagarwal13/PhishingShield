"""Redis connection helper."""

from __future__ import annotations

from typing import Any


def create_redis_client(redis_url: str) -> Any | None:
    """Create a Redis client when the dependency and service are available."""
    try:
        import redis

        client = redis.from_url(redis_url, decode_responses=True)
        client.ping()
        return client
    except Exception:
        return None

