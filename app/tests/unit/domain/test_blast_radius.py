from __future__ import annotations

from datetime import UTC, datetime, timedelta

from domain.entities.alert import Alert
from domain.entities.severity import Severity
from domain.services.blast_radius import correlate_blast_radius

NOW = datetime(2026, 8, 14, 17, 0, 0, tzinfo=UTC)


def _alert(
    *,
    server: str = "core",
    host: str = "node-01",
    alertname: str = "DiskFull",
    app: str = "app",
    starts_at: datetime | None = NOW,
    environment: str = "PRD",
) -> Alert:
    return Alert(
        server=server,
        severity=Severity("critical"),
        alertname=alertname,
        app=app,
        desc=f"{alertname} on {host}",
        status_text="failure",
        starts_at=starts_at,
        host=host,
        environment=environment,
    )


def test_blast_radius_threshold_disabled_or_empty() -> None:
    assert correlate_blast_radius([], threshold=5) == []
    single = _alert()
    assert correlate_blast_radius([single], threshold=1) == [single]


def test_blast_radius_skips_empty_or_na_hosts() -> None:
    first = _alert(host="")
    second = _alert(host="N/A")
    third = _alert(host="node-01")
    result = correlate_blast_radius([first, second, third], threshold=2)
    assert len(result) == 3
    assert result[0] == first
    assert result[1] == second
    assert result[2] == third


def test_blast_radius_consolidates_over_threshold() -> None:
    alerts = [
        _alert(
            host="node-01",
            alertname=f"Service_{i}",
            starts_at=NOW - timedelta(minutes=i),
        )
        for i in range(7)
    ]
    result = correlate_blast_radius(alerts, threshold=5)
    assert len(result) == 1
    consolidated = result[0]
    assert consolidated.alertname == "BlastRadiusDetected"
    assert consolidated.host == "node-01"
    assert consolidated.server == "core"
    assert consolidated.environment == "PRD"
    assert "Falha simultanea de 7 servicos" in consolidated.status_text
    assert "(+2 outros)" in consolidated.status_text
    assert consolidated.starts_at == NOW - timedelta(minutes=6)


def test_blast_radius_starts_at_none_fallback() -> None:
    alerts = [
        _alert(host="node-02", alertname=f"Svc_{i}", starts_at=None, environment="")
        for i in range(5)
    ]
    result = correlate_blast_radius(alerts, threshold=5)
    assert len(result) == 1
    assert result[0].starts_at is None
    assert result[0].environment == ""
