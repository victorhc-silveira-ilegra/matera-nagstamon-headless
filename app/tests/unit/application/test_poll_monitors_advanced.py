from __future__ import annotations

from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo

from application.use_cases.poll_monitors import PollMonitorsUseCase
from domain.entities.alert import Alert
from domain.entities.monitor_server import MonitorServer
from domain.entities.severity import Severity
from domain.services.alert_filter import AlertFilterPolicy

SP_TZ = ZoneInfo("America/Sao_Paulo")
NOW = datetime(2026, 8, 14, 14, 0, 0, tzinfo=SP_TZ)


class FakeServerConfig:
    def __init__(self, servers: list[MonitorServer]) -> None:
        self.servers = servers

    def list_enabled(self) -> list[MonitorServer]:
        return list(self.servers)


class FakeMonitorClient:
    def __init__(self, alerts: list[Alert]) -> None:
        self.alerts = alerts

    def fetch_all(self, servers: list[MonitorServer]) -> list[Alert]:
        _ = servers
        return list(self.alerts)


class FakeAlertSink:
    def __init__(self) -> None:
        self.published: list[Alert] = []
        self.texts: list[str] = []
        self.thread_keys: list[str | None] = []

    def publish(
        self,
        alerts: list[Alert],
        *,
        fetched_at: datetime,
        thread_key: str | None = None,
    ) -> None:
        _ = fetched_at
        self.published.extend(alerts)
        self.thread_keys.append(thread_key)

    def publish_text(
        self,
        text: str,
        *,
        thread_key: str | None = None,
    ) -> None:
        self.texts.append(text)
        self.thread_keys.append(thread_key)


class FakeClock:
    def __init__(self, current: datetime) -> None:
        self.current = current

    def now(self) -> datetime:
        return self.current


class FakeAdvancedLedger:
    def __init__(self, resolved_records: list[dict[str, str]] | None = None) -> None:
        self.resolved_records = resolved_records or []
        self.claims: set[str] = set()

    def try_claim(
        self, *, fingerprint: str, now: datetime, window_minutes: int
    ) -> bool:
        _ = (now, window_minutes)
        if fingerprint in self.claims:
            return False
        self.claims.add(fingerprint)
        return True

    def confirm(
        self,
        *,
        fingerprint: str,
        now: datetime,
        meta: dict[str, str] | None = None,
    ) -> None:
        _ = (fingerprint, now, meta)

    def release(self, *, fingerprint: str) -> None:
        self.claims.discard(fingerprint)

    def reconcile_active(
        self,
        *,
        active_fingerprints: frozenset[str],
        now: datetime,
        window_minutes: int,
        polled_servers: frozenset[str] | None = None,
    ) -> list[dict[str, str]]:
        _ = (active_fingerprints, now, window_minutes, polled_servers)
        return list(self.resolved_records)


def _server(name: str = "core") -> MonitorServer:
    return MonitorServer(
        name=name,
        url=f"http://{name}.example",
        proxy="",
        username="",
        password="",
        server_type="nagios",
    )


def _alert(
    *,
    server: str = "core",
    host: str = "node-01",
    alertname: str = "DiskFull",
    app: str = "app",
    starts_at: datetime | None = NOW - timedelta(minutes=25),
) -> Alert:
    return Alert(
        server=server,
        severity=Severity("critical"),
        alertname=alertname,
        app=app,
        desc=f"{alertname} on {host}",
        status_text="crit",
        starts_at=starts_at,
        host=host,
    )


def test_use_case_blast_radius_consolidation() -> None:
    alerts = [_alert(host="worker-01", alertname=f"Check_{i}") for i in range(5)]
    sink = FakeAlertSink()
    use_case = PollMonitorsUseCase(
        server_config=FakeServerConfig([_server("core")]),  # type: ignore[arg-type]
        monitor_client=FakeMonitorClient(alerts),  # type: ignore[arg-type]
        alert_sink=sink,  # type: ignore[arg-type]
        clock=FakeClock(NOW),
        filter_policy=AlertFilterPolicy(window_enabled=False),
        dispatch_ledger=FakeAdvancedLedger(),
        blast_radius_threshold=5,
        heartbeat_enabled=False,
    )
    result = use_case.execute()
    assert result.alerts_count == 1
    assert result.claimed_count == 1
    assert len(sink.published) == 1
    assert sink.published[0].alertname == "BlastRadiusDetected"
    assert sink.published[0].host == "worker-01"


def test_use_case_resolved_notifications() -> None:
    resolved_records = [
        {
            "server": "core",
            "target": "order-api",
            "incident_id": "core:order-api",
            "thread_key": "core:k8s:order-api",
            "sent_at": (NOW - timedelta(minutes=34)).isoformat(),
        },
        {
            "server": "core",
            "target": "pay-api",
            "incident_id": "core:pay-api",
            "thread_key": "core:k8s:pay-api",
            "sent_at": "invalid_date",
        },
        {
            "server": "core",
            "target": "user-api",
            "incident_id": "core:user-api",
            "thread_key": "core:k8s:user-api",
            "sent_at": "",
        },
    ]
    sink = FakeAlertSink()
    use_case = PollMonitorsUseCase(
        server_config=FakeServerConfig([_server("core")]),  # type: ignore[arg-type]
        monitor_client=FakeMonitorClient([]),  # type: ignore[arg-type]
        alert_sink=sink,  # type: ignore[arg-type]
        clock=FakeClock(NOW),
        filter_policy=AlertFilterPolicy(window_enabled=False),
        dispatch_ledger=FakeAdvancedLedger(resolved_records),
        heartbeat_enabled=False,
    )
    result = use_case.execute()
    assert result.claimed_count == 0
    assert len(sink.texts) == 3
    assert "[RESOLVIDO] core / order-api normalizado após 34 minutos." in sink.texts[0]
    assert "Horário da resolução: " in sink.texts[0]
    assert sink.thread_keys[0] == "core:k8s:order-api"

    assert "[RESOLVIDO] core / pay-api normalizado." in sink.texts[1]
    assert "Horário da resolução: " in sink.texts[1]
    assert sink.thread_keys[1] == "core:k8s:pay-api"


def test_use_case_heartbeat_window_start_and_end() -> None:
    policy = AlertFilterPolicy(
        window_enabled=True,
        window_start=time(13, 30),
        window_end=time(18, 0),
        timezone=SP_TZ,
    )
    sink = FakeAlertSink()
    start_time = datetime(2026, 8, 14, 13, 35, 0, tzinfo=SP_TZ)
    clock = FakeClock(start_time)
    use_case = PollMonitorsUseCase(
        server_config=FakeServerConfig([_server("core")]),  # type: ignore[arg-type]
        monitor_client=FakeMonitorClient([]),  # type: ignore[arg-type]
        alert_sink=sink,  # type: ignore[arg-type]
        clock=clock,
        filter_policy=policy,
        dispatch_ledger=None,
        heartbeat_enabled=True,
    )
    use_case.execute()
    assert len(sink.texts) == 1
    assert "*STATUS DO MONITOR*" in sink.texts[0]
    assert "🟢" not in sink.texts[0]

    use_case.execute()
    assert len(sink.texts) == 1

    clock.current = datetime(2026, 8, 14, 18, 5, 0, tzinfo=SP_TZ)
    use_case.execute()
    assert len(sink.texts) == 2
    assert "*STATUS DO MONITOR*" in sink.texts[1]
    assert "🟢" not in sink.texts[1]


def test_use_case_heartbeat_skips_outside_weekdays_or_disabled() -> None:
    policy = AlertFilterPolicy(
        window_enabled=True,
        window_start=time(13, 30),
        window_end=time(18, 0),
        weekdays=(0, 1, 2, 3, 4),
        timezone=SP_TZ,
    )
    sink = FakeAlertSink()
    saturday_noon = datetime(2026, 8, 15, 14, 0, 0, tzinfo=SP_TZ)
    use_case = PollMonitorsUseCase(
        server_config=FakeServerConfig([_server("core")]),  # type: ignore[arg-type]
        monitor_client=FakeMonitorClient([]),  # type: ignore[arg-type]
        alert_sink=sink,  # type: ignore[arg-type]
        clock=FakeClock(saturday_noon),
        filter_policy=policy,
        dispatch_ledger=None,
        heartbeat_enabled=True,
    )
    use_case.execute()
    assert len(sink.texts) == 0

    friday_noon = datetime(2026, 8, 14, 12, 0, 0, tzinfo=SP_TZ)
    use_case_early = PollMonitorsUseCase(
        server_config=FakeServerConfig([_server("core")]),  # type: ignore[arg-type]
        monitor_client=FakeMonitorClient([]),  # type: ignore[arg-type]
        alert_sink=sink,  # type: ignore[arg-type]
        clock=FakeClock(friday_noon),
        filter_policy=policy,
        dispatch_ledger=None,
        heartbeat_enabled=True,
    )
    use_case_early.execute()
    assert len(sink.texts) == 0
