from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from application.ports.alert_dispatch_ledger import AlertDispatchLedgerPort
from application.ports.alert_sink import AlertSinkPort
from application.ports.alert_sound import AlertSoundPort
from application.ports.clock import ClockPort
from application.ports.monitor_client import MonitorClientPort
from application.ports.server_config import ServerConfigPort
from domain.entities.alert import Alert
from domain.services.alert_filter import AlertFilterPolicy
from domain.services.blast_radius import correlate_blast_radius
from domain.services.operational_view import render_heartbeat, render_resolved_alert


@dataclass(frozen=True, slots=True)
class PollCycleResult:
    servers_count: int
    alerts_count: int
    claimed_count: int = 0
    skipped_duplicate_count: int = 0


def fingerprint_for(alert: Alert) -> str:
    return hashlib.sha256(alert.dedup_key().encode()).hexdigest()


def _alert_priority_rank(alert: Alert) -> tuple[int, int, str]:
    severity_order = 0 if alert.severity.value == "CRITICAL" else 1
    name = alert.alertname.lower()
    if any(
        k in name
        for k in (
            "allreplicasdown",
            "deploymentcrashloopbackoff",
            "oomkilled",
            "imagepull",
            "app health",
        )
    ):
        name_order = 0
    elif any(k in name for k in ("crashloop", "podnotready", "backoff")):
        name_order = 1
    elif any(k in name for k in ("targetdown", "errormessages")):
        name_order = 2
    else:
        name_order = 3
    return severity_order, name_order, alert.alertname.lower()


def _unique_by_dedup_key(alerts: Sequence[Alert]) -> tuple[list[Alert], int]:
    groups: dict[str, list[Alert]] = {}
    for alert in alerts:
        groups.setdefault(alert.dedup_key(), []).append(alert)
    unique: list[Alert] = []
    intra_skipped = 0
    for group in groups.values():
        best = min(group, key=_alert_priority_rank)
        unique.append(best)
        intra_skipped += len(group) - 1
    return unique, intra_skipped


class PollMonitorsUseCase:
    def __init__(
        self,
        server_config: ServerConfigPort,
        monitor_client: MonitorClientPort,
        alert_sink: AlertSinkPort,
        clock: ClockPort,
        filter_policy: AlertFilterPolicy | None = None,
        dispatch_ledger: AlertDispatchLedgerPort | None = None,
        alert_sound: AlertSoundPort | None = None,
        dedup_window_minutes: int = 240,
        blast_radius_threshold: int = 5,
        heartbeat_enabled: bool = True,
    ) -> None:
        self._server_config = server_config
        self._monitor_client = monitor_client
        self._alert_sink = alert_sink
        self._clock = clock
        self._filter_policy = filter_policy or AlertFilterPolicy()
        self._dispatch_ledger = dispatch_ledger
        self._alert_sound = alert_sound
        self._dedup_window_minutes = dedup_window_minutes
        self._blast_radius_threshold = blast_radius_threshold
        self._heartbeat_enabled = heartbeat_enabled
        self._last_heartbeat_start_date: object = None
        self._last_heartbeat_end_date: object = None

    def _play_new_alert(self) -> None:
        if self._alert_sound is not None:
            self._alert_sound.play_new_alert()

    def _evaluate_heartbeat(self, now: datetime, servers_count: int) -> None:
        if (
            not self._heartbeat_enabled
            or not self._filter_policy._window_enabled
            or servers_count == 0
        ):
            return
        local_now = now.astimezone(self._filter_policy._timezone)
        if local_now.weekday() not in self._filter_policy._weekdays:
            return
        today = local_now.date()
        current_time = local_now.time()
        start = self._filter_policy._window_start
        end = self._filter_policy._window_end
        if current_time >= start and self._last_heartbeat_start_date != today:
            self._last_heartbeat_start_date = today
            text = render_heartbeat(
                servers_count=servers_count,
                checked_at=now,
                timezone=self._filter_policy._timezone,
            )
            self._alert_sink.publish_text(text)
        elif current_time >= end and self._last_heartbeat_end_date != today:
            self._last_heartbeat_end_date = today
            text = render_heartbeat(
                servers_count=servers_count,
                checked_at=now,
                timezone=self._filter_policy._timezone,
            )
            self._alert_sink.publish_text(text)

    def _notify_resolved(
        self,
        resolved_records: list[dict[str, str]],
        now: datetime,
    ) -> None:
        for record in resolved_records:
            server = record.get("server", "")
            target = record.get("target", "")
            incident_id = record.get("incident_id", "")
            thread_key = record.get("thread_key")
            sent_at_str = record.get("sent_at", "")
            duration_min = None
            if sent_at_str:
                try:
                    sent_at = datetime.fromisoformat(sent_at_str)
                    duration_min = int((now - sent_at).total_seconds() / 60)
                except ValueError:
                    duration_min = None
            text = render_resolved_alert(
                server=server,
                target=target,
                incident_id=incident_id,
                resolved_at=now,
                duration_minutes=duration_min,
                timezone=self._filter_policy._timezone,
            )
            self._alert_sink.publish_text(text, thread_key=thread_key)

    def execute(self) -> PollCycleResult:
        servers = list(self._server_config.list_enabled())
        raw_alerts = list(self._monitor_client.fetch_all(servers))
        now = self._clock.now()
        effective = self._filter_policy.apply(raw_alerts, now)
        effective = correlate_blast_radius(
            effective, threshold=self._blast_radius_threshold
        )
        if self._dispatch_ledger is None:
            self._alert_sink.publish(effective, fetched_at=now)
            if effective:
                self._play_new_alert()
            self._evaluate_heartbeat(now, len(servers))
            return PollCycleResult(
                servers_count=len(servers),
                alerts_count=len(effective),
                claimed_count=len(effective),
                skipped_duplicate_count=0,
            )
        active_fingerprints = frozenset(fingerprint_for(alert) for alert in raw_alerts)
        polled_servers = frozenset(s.name for s in servers)
        resolved = self._dispatch_ledger.reconcile_active(
            active_fingerprints=active_fingerprints,
            now=now,
            window_minutes=self._dedup_window_minutes,
            polled_servers=polled_servers,
        )
        self._notify_resolved(resolved, now)
        unique, intra_skipped = _unique_by_dedup_key(effective)
        claimed: list[Alert] = []
        skipped = intra_skipped
        for alert in unique:
            fingerprint = fingerprint_for(alert)
            if not self._dispatch_ledger.try_claim(
                fingerprint=fingerprint,
                now=now,
                window_minutes=self._dedup_window_minutes,
            ):
                skipped += 1
                continue
            try:
                self._alert_sink.publish(
                    [alert], fetched_at=now, thread_key=alert.thread_key()
                )
            except Exception:
                self._dispatch_ledger.release(fingerprint=fingerprint)
                continue
            meta = {
                "server": alert.server,
                "target": alert.canonical_workload(),
                "incident_id": alert.incident_key(),
                "thread_key": alert.thread_key(),
            }
            self._dispatch_ledger.confirm(fingerprint=fingerprint, now=now, meta=meta)
            claimed.append(alert)
        if claimed:
            self._play_new_alert()
        self._evaluate_heartbeat(now, len(servers))
        return PollCycleResult(
            servers_count=len(servers),
            alerts_count=len(effective),
            claimed_count=len(claimed),
            skipped_duplicate_count=skipped,
        )
