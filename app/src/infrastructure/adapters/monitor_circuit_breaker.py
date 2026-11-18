from __future__ import annotations

import threading
from datetime import datetime, timedelta


class MonitorCircuitBreaker:
    def __init__(
        self,
        max_failures: int = 3,
        cooldown_seconds: int = 300,
    ) -> None:
        self._max_failures = max(1, max_failures)
        self._cooldown = timedelta(seconds=max(1, cooldown_seconds))
        self._lock = threading.Lock()
        self._failures: dict[str, int] = {}
        self._open_until: dict[str, datetime] = {}

    def is_available(self, server_name: str, now: datetime) -> bool:
        with self._lock:
            open_until = self._open_until.get(server_name)
            if open_until is None:
                return True
            if now >= open_until:
                self._open_until.pop(server_name, None)
                return True
            return False

    def record_success(self, server_name: str) -> None:
        with self._lock:
            self._failures.pop(server_name, None)
            self._open_until.pop(server_name, None)

    def record_failure(self, server_name: str, now: datetime) -> None:
        with self._lock:
            count = self._failures.get(server_name, 0) + 1
            self._failures[server_name] = count
            if count >= self._max_failures:
                self._open_until[server_name] = now + self._cooldown
