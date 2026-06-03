"""In-memory rate limiter for login endpoints."""
from __future__ import annotations

import time
from collections import defaultdict


class LoginRateLimiter:
    """Simple sliding-window rate limiter keyed by IP address."""

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self._attempts: dict[str, list[float]] = defaultdict(list)
        self._max = max_attempts
        self._window = window_seconds

    def check(self, ip: str) -> bool:
        """Return True if the request is allowed (under the limit)."""
        now = time.time()
        self._attempts[ip] = [t for t in self._attempts[ip] if now - t < self._window]
        return len(self._attempts[ip]) < self._max

    def record(self, ip: str) -> None:
        """Record a failed attempt."""
        self._attempts[ip].append(time.time())

    def remaining(self, ip: str) -> int:
        """Return remaining attempts in the current window."""
        now = time.time()
        attempts = [t for t in self._attempts[ip] if now - t < self._window]
        return max(0, self._max - len(attempts))
