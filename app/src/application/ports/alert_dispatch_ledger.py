from __future__ import annotations

from datetime import datetime
from typing import Protocol


class AlertDispatchLedgerPort(Protocol):
    def try_claim(
        self,
        *,
        fingerprint: str,
        now: datetime,
        window_minutes: int,
    ) -> bool: ...

    def confirm(
        self,
        *,
        fingerprint: str,
        now: datetime,
        meta: dict[str, str] | None = None,
    ) -> None: ...

    def release(self, *, fingerprint: str) -> None: ...

    def reconcile_active(
        self,
        *,
        active_fingerprints: frozenset[str],
        now: datetime,
        window_minutes: int,
        polled_servers: frozenset[str] | None = None,
    ) -> list[dict[str, str]]: ...
