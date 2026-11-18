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
    assert "*Status:* RESOLVIDO" in text
    assert "*Client:* core-nagios" in text
    assert "*Alvo:* db-cluster" in text
    assert "*Duração aproximada:* 42m" in text
    assert "*ID do Incidente (SLA):* core/Disk/db01" in text


def test_render_resolved_alert_without_duration() -> None:
    text = render_resolved_alert(
        server="am",
        target="pod-x",
        incident_id="am/k8s/pod-x",
        resolved_at=NOW,
        duration_minutes=None,
    )
    assert "*Duração aproximada:* --" in text


def test_render_heartbeat() -> None:
    text = render_heartbeat(
        servers_count=96,
        checked_at=NOW,
        timezone=SP_TZ,
    )
    assert "🟢 *STATUS DO MONITOR*" in text
    assert "96 servidores monitorados com sucesso" in text
