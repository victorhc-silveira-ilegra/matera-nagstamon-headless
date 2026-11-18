from __future__ import annotations

import logging
import threading
from collections.abc import Sequence
from datetime import datetime
from zoneinfo import ZoneInfo

import httpx

from domain.entities.alert import Alert
from domain.services.alert_view import DISPLAY_TIMEZONE, render_effective_alerts
from infrastructure.adapters.http_client import USER_AGENT, DnsResolvingProxyTransport
from infrastructure.logging import (
    POLL_GCHAT_FAILED,
    POLL_GCHAT_PUBLISHED,
    log_event,
    redact_url,
)

logger = logging.getLogger(__name__)


class GoogleChatDeliveryError(RuntimeError):
    pass


class GoogleChatWebhookSink:
    def __init__(
        self,
        webhook_url: str,
        *,
        timeout_seconds: float,
        proxy: str = "",
        timezone: ZoneInfo | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._webhook_url = webhook_url
        self._timezone = timezone or DISPLAY_TIMEZONE
        self._lock = threading.Lock()
        resolved_transport = transport
        if resolved_transport is None and proxy:
            resolved_transport = DnsResolvingProxyTransport(proxy=proxy, verify=False)
        self._client = httpx.Client(
            timeout=timeout_seconds,
            proxy=None if resolved_transport is not None else (proxy or None),
            transport=resolved_transport,
            headers=USER_AGENT,
        )

    def publish(
        self,
        alerts: Sequence[Alert],
        *,
        fetched_at: datetime,
        thread_key: str | None = None,
    ) -> None:
        if not alerts:
            return
        text = render_effective_alerts(alerts, fetched_at, self._timezone)
        resolved_thread = thread_key or (
            alerts[0].thread_key() if len(alerts) == 1 else None
        )
        self.publish_text(text, thread_key=resolved_thread)

    def publish_text(
        self,
        text: str,
        *,
        thread_key: str | None = None,
    ) -> None:
        if not text.strip():
            return
        payload: dict[str, object] = {"text": text}
        if thread_key:
            payload["thread"] = {"threadKey": thread_key}
        url = self._webhook_url
        if thread_key and "messageReplyOption" not in url:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}messageReplyOption=REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"
        with self._lock:
            try:
                response = self._client.post(url, json=payload)
            except Exception as exc:
                self._log_failed(type(exc).__name__)
                raise GoogleChatDeliveryError(type(exc).__name__) from exc
            if response.is_success:
                log_event(
                    logger,
                    logging.INFO,
                    POLL_GCHAT_PUBLISHED,
                    alerts_count=1,
                )
                return
            self._log_failed("http_status", http_status=response.status_code)
            raise GoogleChatDeliveryError("http_status")

    def _log_failed(self, error_type: str, *, http_status: int | None = None) -> None:
        fields: dict[str, object] = {
            "error_type": error_type,
            "webhook_host": redact_url(self._webhook_url),
        }
        if http_status is not None:
            fields["http_status"] = http_status
        log_event(
            logger,
            logging.WARNING,
            POLL_GCHAT_FAILED,
            exc_info=logger.isEnabledFor(logging.DEBUG),
            **fields,
        )
