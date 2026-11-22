"""Process-local login failure limits.

Each API process keeps its own counters. A second worker or a second
instance does not see them. This is not a distributed rate limit.
"""
import threading
import time

from fastapi import HTTPException, status


class LoginRateLimiter:
    def __init__(self, email_limit: int = 5, ip_limit: int = 30, window_seconds: int = 900):
        self.email_limit = email_limit
        self.ip_limit = ip_limit
        self.window_seconds = window_seconds
        self._email_failures: dict[str, list[float]] = {}
        self._ip_failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def reset(self) -> None:
        with self._lock:
            self._email_failures.clear()
            self._ip_failures.clear()

    def enforce(self, email: str, client_host: str) -> None:
        """Reject the attempt when this process has already recorded enough failures."""
        now = time.monotonic()
        with self._lock:
            retry_after = self._retry_after(self._email_failures, email, self.email_limit, now)
            if retry_after is None:
                retry_after = self._retry_after(self._ip_failures, client_host, self.ip_limit, now)
        if retry_after is not None:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts. Try again later.",
                headers={"Retry-After": str(retry_after)},
            )

    def record_failure(self, email: str, client_host: str) -> None:
        now = time.monotonic()
        with self._lock:
            self._email_failures[email] = self._prune(self._email_failures.get(email, []), now) + [now]
            self._ip_failures[client_host] = self._prune(self._ip_failures.get(client_host, []), now) + [now]

    def _prune(self, stamps: list[float], now: float) -> list[float]:
        return [stamp for stamp in stamps if now - stamp < self.window_seconds]

    def _retry_after(self, store: dict[str, list[float]], key: str, limit: int, now: float) -> int | None:
        recent = self._prune(store.get(key, []), now)
        store[key] = recent
        if len(recent) < limit:
            return None
        return max(1, int(self.window_seconds - (now - recent[0])) + 1)


login_rate_limiter = LoginRateLimiter()
