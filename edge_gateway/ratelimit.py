"""Per-identity sliding-window rate limiter (thread safe).

A deque of request timestamps is kept per identity. Every check is performed
under a single lock, so concurrent requests can neither lose nor double-count
hits. Boundary behavior is deterministic: when the window already contains
``effective_limit`` timestamps, the next request is denied.
"""

from __future__ import annotations

import math
import threading
from collections import defaultdict, deque
from typing import Any

from edge_gateway.clock import Clock, SystemClock


class SlidingWindowRateLimiter:
    def __init__(
        self,
        limit: int,
        window_seconds: float,
        clock: Clock | None = None,
    ) -> None:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        self.base_limit = limit
        self.window_seconds = float(window_seconds)
        self._clock = clock or SystemClock()
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _effective_limit(self, multiplier: float) -> int:
        # Recovery stages shrink the quota; at least one request must remain
        # possible, otherwise a client could never prove good behavior.
        return max(1, math.floor(self.base_limit * multiplier))

    def _prune_locked(self, bucket: deque[float], now: float) -> None:
        boundary = now - self.window_seconds
        while bucket and bucket[0] <= boundary:
            bucket.popleft()

    def check_and_consume(
        self,
        identity: str,
        multiplier: float = 1.0,
    ) -> tuple[bool, dict[str, Any]]:
        """Atomically evict expired hits, test the quota and record the hit."""
        effective_limit = self._effective_limit(multiplier)
        with self._lock:
            now = self._clock.now()
            bucket = self._hits[identity]
            self._prune_locked(bucket, now)
            used = len(bucket)
            if used >= effective_limit:
                oldest = bucket[0]
                retry_after = max(0.0, oldest + self.window_seconds - now)
                return False, {
                    "limit": effective_limit,
                    "base_limit": self.base_limit,
                    "window_seconds": self.window_seconds,
                    "used": used,
                    "remaining": 0,
                    "retry_after": round(retry_after, 6),
                    "window_start": oldest,
                    "window_end": oldest + self.window_seconds,
                }
            bucket.append(now)
            return True, {
                "limit": effective_limit,
                "base_limit": self.base_limit,
                "window_seconds": self.window_seconds,
                "used": used + 1,
                "remaining": effective_limit - used - 1,
                "window_start": bucket[0],
                "window_end": now + self.window_seconds,
            }

    def snapshot(self, identity: str) -> dict[str, Any]:
        """Return the post-eviction window state without consuming a slot."""
        with self._lock:
            now = self._clock.now()
            bucket = self._hits.get(identity)
            if bucket is None:
                return {
                    "used": 0,
                    "window_seconds": self.window_seconds,
                    "oldest": None,
                    "newest": None,
                }
            self._prune_locked(bucket, now)
            return {
                "used": len(bucket),
                "window_seconds": self.window_seconds,
                "oldest": bucket[0] if bucket else None,
                "newest": bucket[-1] if bucket else None,
            }

    def reset(self, identity: str | None = None) -> None:
        with self._lock:
            if identity is None:
                self._hits.clear()
            else:
                self._hits.pop(identity, None)
