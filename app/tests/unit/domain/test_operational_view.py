from __future__ import annotations

from datetime import UTC, datetime
from zoneinfo import ZoneInfo

from domain.services.operational_view import render_heartbeat, render_resolved_alert

NOW = datetime(2026, 8, 14, 17, 30, 0, tzinfo=UTC)
SP_TZ = ZoneInfo("America/Sao_Paulo")


def test_render_resolved_alert_with_duration() -> None:
    text = render_resolved_alert(
        server="core-nagios",
        target="db-cluster",
        incident_id="core/Disk/db01",
        resolved_at=NOW,
        duration_minutes=42,
        timezone=SP_TZ,
    )
    assert (
        text == "[RESOLVIDO] core-nagios / db-cluster normalizado após 42 minutos.\n"
        "Horário da resolução: 14/08/2026 - 14:30:00"
    )


def test_render_resolved_alert_without_duration() -> None:
    text = render_resolved_alert(
        server="am",
        target="pod-x",
        incident_id="am/k8s/pod-x",
        resolved_at=NOW,
        duration_minutes=None,
    )
    assert "[RESOLVIDO] am / pod-x normalizado.\n" in text
    assert "Horário da resolução: 14/08/2026 - 14:30:00" in text


def test_render_heartbeat() -> None:
    text = render_heartbeat(
        servers_count=96,
        checked_at=NOW,
        timezone=SP_TZ,
    )
    assert "*STATUS DO MONITOR* (14/08/2026 - 14:30:00)" in text
    assert "🟢" not in text
    assert "96 servidores monitorados com sucesso" in text
