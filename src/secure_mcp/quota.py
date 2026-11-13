"""Per-user call quota over a sliding window.

In memory and per process: a restart resets it, and several server replicas
would each keep their own count. A shared store (Redis, the database) is the
production version; the interface stays the same.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable


class QuotaExceeded(Exception):
    pass


class SlidingWindowQuota:
    def __init__(self, limit: int, window_seconds: float, clock: Callable[[], float] = time.monotonic):
        if limit < 1 or window_seconds <= 0:
            raise ValueError("limit and window must be positive")
        self.limit = limit
        self.window = window_seconds
        self.clock = clock
        self._calls: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def consume(self, subject: str) -> None:
        """Count one call for ``subject`` or raise QuotaExceeded."""
        now = self.clock()
        with self._lock:
            calls = self._calls[subject]
            while calls and calls[0] <= now - self.window:
                calls.popleft()
            if len(calls) >= self.limit:
                raise QuotaExceeded(f"quota of {self.limit} calls per {self.window:g}s reached")
            calls.append(now)
