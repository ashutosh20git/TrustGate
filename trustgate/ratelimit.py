"""Rate limiter: Redis fixed-window counters (blueprint: Redis token bucket).

Floods of T0 actions are an IOC (silent failure 22). If Redis is down the
limiter raises, and the gate fails closed for T1-T3.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Protocol

from trustgate.config import NotConfigured, Settings

WINDOW_S = 60


class RateLimiter(Protocol):
    def hit(self, bucket: str, limit: int) -> bool:
        """Count one action in bucket; True if still within limit for this window."""


class RedisRateLimiter:
    def __init__(self, url: str | None = None, *, client=None):
        if client is None:
            if not url:
                raise NotConfigured("REDIS_URL", "start Redis or set TRUSTGATE_RATELIMIT_BACKEND=memory for one process")
            import redis

            client = redis.Redis.from_url(url, socket_timeout=2, socket_connect_timeout=2)
        self._redis = client

    def hit(self, bucket: str, limit: int) -> bool:
        window = int(time.time() // WINDOW_S)
        key = f"tg:rl:{bucket}:{window}"
        pipe = self._redis.pipeline()
        pipe.incr(key)
        pipe.expire(key, WINDOW_S * 2)
        count, _ = pipe.execute()
        return int(count) <= limit


class MemoryRateLimiter:
    """Single-process limiter for development and tests only."""

    def __init__(self):
        self._counts: dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

    def hit(self, bucket: str, limit: int) -> bool:
        key = f"{bucket}:{int(time.time() // WINDOW_S)}"
        with self._lock:
            self._counts[key] += 1
            return self._counts[key] <= limit


class UnavailableRateLimiter:
    def __init__(self, error: Exception):
        self._error = error

    def hit(self, bucket: str, limit: int) -> bool:
        raise self._error


def rate_limiter(settings: Settings) -> RateLimiter:
    if settings.ratelimit_backend == "memory":
        return MemoryRateLimiter()
    try:
        return RedisRateLimiter(settings.redis_url)
    except NotConfigured as exc:
        return UnavailableRateLimiter(exc)
