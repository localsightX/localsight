"""In-memory token-bucket rate limiter.

Sufficient for a single-process deployment. For multi-worker / multi-host
deployments, swap the backing store for Redis (the class interface is stable).
Design: each (key, bucket) starts with `capacity` tokens and refills at
`rate` tokens/second. A request consumes one token; when empty, the request is
rejected.
"""
from __future__ import annotations

import threading
import time


class RateLimiter:
    def __init__(self, max_buckets: int = 10000) -> None:
        self._buckets: dict[tuple[str, str], list[float]] = {}
        self._lock = threading.Lock()
        self._max_buckets = max_buckets

    def bucket_count(self) -> int:
        """Current table size (observability for the bound above)."""
        with self._lock:
            return len(self._buckets)

    def allow(self, key: str, bucket: str, rate: float, capacity: int) -> bool:
        now = time.monotonic()
        bk = (key, bucket)
        with self._lock:
            # Bound memory: an unauthenticated attacker can mint unlimited distinct
            # keys (IPs) cheaply; without eviction the bucket dict grows forever.
            # Opportunistically drop buckets that have fully refilled with THIS
            # call's rate (a full bucket behaves identically to an absent one on
            # next `allow`, so eviction is invisible to legitimate clients — only
            # idle attack keys disappear). Buckets on a slower refill schedule
            # are conservatively kept; worst case the table briefly exceeds the
            # cap under a mixed-rate flood. O(n) but amortized: it only runs
            # after the table passes the cap.
            if len(self._buckets) > self._max_buckets:
                stale = [other for other, (level, last) in self._buckets.items()
                         if other != bk and min(capacity, level + (now - last) * rate) >= capacity]
                for other in stale:
                    del self._buckets[other]
            state = self._buckets.get(bk)  # (level, last_seen)
            if state is None:
                # first request consumes one token
                self._buckets[bk] = (capacity - 1, now)
                return True
            level, last = state
            # refill proportionally to elapsed time
            level = min(capacity, level + (now - last) * rate)
            if level < 1:
                self._buckets[bk] = (level, now)
                return False
            self._buckets[bk] = (level - 1, now)
            return True

    def reset(self, key: str, bucket: str) -> None:
        with self._lock:
            self._buckets.pop((key, bucket), None)

    def clear(self) -> None:
        """Drop all state. Used between tests and on configuration reload."""
        with self._lock:
            self._buckets.clear()


# Process-wide default limiter (login is the strictest bucket).
limiter = RateLimiter()
