from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from application.ports.alert_sink import AlertSinkPort
from domain.entities.alert import Alert


class CompositeAlertSink:
    def __init__(self, *sinks: AlertSinkPort) -> None:
        self._sinks = sinks

    def publish(
        self,
        alerts: Sequence[Alert],
        *,
        fetched_at: datetime,
        thread_key: str | None = None,
    ) -> None:
        for sink in self._sinks:
            sink.publish(alerts, fetched_at=fetched_at, thread_key=thread_key)

    def publish_text(
        self,
        text: str,
        *,
        thread_key: str | None = None,
    ) -> None:
        for sink in self._sinks:
            sink.publish_text(text, thread_key=thread_key)
