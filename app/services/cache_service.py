"""Cache abstraction with Redis-compatible semantics."""

from __future__ import annotations

import json
from typing import Any


class CacheService:
    """JSON cache wrapper that degrades cleanly when Redis is unavailable."""

    def __init__(self, client: Any = None, default_ttl_seconds: int = 3600) -> None:
        self.client = client
        self.default_ttl_seconds = default_ttl_seconds
        self.hits = 0
        self.misses = 0

    def get_json(self, key: str) -> dict[str, Any] | None:
        if not self.client:
            self.misses += 1
            return None
        try:
            raw = self.client.get(key)
            if raw is None:
                self.misses += 1
                return None
            self.hits += 1
            return json.loads(raw)
        except Exception:
            self.misses += 1
            return None

    def set_json(self, key: str, value: dict[str, Any], ttl_seconds: int | None = None) -> None:
        if not self.client:
            return
        try:
            self.client.set(key, json.dumps(value), ex=ttl_seconds or self.default_ttl_seconds)
        except Exception:
            return

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total else 0.0

