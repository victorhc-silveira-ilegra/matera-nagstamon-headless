from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

from domain.services.alert_view import (
    DISPLAY_TIMEZONE,
    display_value,
    format_clock_time,
)


def render_resolved_alert(
    *,
    server: str,
    target: str,
    incident_id: str,
    resolved_at: datetime,
    duration_minutes: int | None = None,
    timezone: ZoneInfo | None = None,
) -> str:
    zone = timezone or DISPLAY_TIMEZONE
    clock_str = format_clock_time(resolved_at, zone)
    duration_suffix = (
        f" normalizado após {duration_minutes} minutos."
        if duration_minutes is not None and duration_minutes > 0
        else " normalizado."
    )
    srv = display_value(server)
    tgt = display_value(target)
    return (
        f"[RESOLVIDO] {srv} / {tgt}{duration_suffix}\nHorário da resolução: {clock_str}"
    )


def render_heartbeat(
    *,
    servers_count: int,
    checked_at: datetime,
    timezone: ZoneInfo | None = None,
) -> str:
    zone = timezone or DISPLAY_TIMEZONE
    clock_str = format_clock_time(checked_at, zone)
    return (
        f"*STATUS DO MONITOR* ({clock_str})\n"
        f"Nagstamon Headless ativo e operacional. "
        f"{servers_count} servidores monitorados com sucesso, "
        "0 incidentes pendentes."
    )
