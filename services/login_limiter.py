"""Brute-force protection for login.

After LOGIN_MAX_ATTEMPTS failed logins for the same email from the same IP within
LOGIN_LOCKOUT_MINUTES, further attempts get HTTP 429 until the window passes.
A successful login clears the counter.

State is kept in memory per worker process. With several gunicorn workers each
keeps its own count; use a shared store (e.g. Redis) if you need one global limit.
"""
import math
import threading
import time

from fastapi import HTTPException, Request, status

from config import settings


class LoginLimiter:
    def __init__(self, max_attempts: int, window_seconds: int):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: str, now: float) -> list[float]:
        attempts = [t for t in self._failures.get(key, []) if now - t < self.window_seconds]
        if attempts:
            self._failures[key] = attempts
        else:
            self._failures.pop(key, None)
        return attempts

    def check(self, key: str) -> None:
        """Raise 429 if this key is currently locked out."""
        now = time.monotonic()
        with self._lock:
            attempts = self._recent(key, now)
            if len(attempts) >= self.max_attempts:
                retry_after = math.ceil(self.window_seconds - (now - attempts[0]))
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many failed login attempts. Please try again later.",
                    headers={"Retry-After": str(max(retry_after, 1))},
                )

    def record_failure(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            self._recent(key, now)
            self._failures.setdefault(key, []).append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


def login_key(request: Request, portal: str, email: str) -> str:
    ip = request.client.host if request.client else "unknown"
    return f"{portal}|{ip}|{email.strip().lower()}"


login_limiter = LoginLimiter(
    max_attempts=settings.LOGIN_MAX_ATTEMPTS,
    window_seconds=settings.LOGIN_LOCKOUT_MINUTES * 60,
)
