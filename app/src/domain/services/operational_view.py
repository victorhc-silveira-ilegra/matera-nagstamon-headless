from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

from domain.services.alert_view import (
    DISPLAY_TIMEZONE,
    MISSING,
    _labeled,
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
    duration_str = (
        f"{duration_minutes}m"
        if duration_minutes is not None and duration_minutes >= 0
        else MISSING
    )
    return "\n".join(
        [
            _labeled("Status", "RESOLVIDO"),
            _labeled("Client", display_value(server)),
            _labeled("Alvo", display_value(target)),
            _labeled("Horário da resolução", clock_str),
            _labeled("Duração aproximada", duration_str),
            _labeled(
                "Status information",
                "O incidente foi normalizado e não está mais ativo na "
                "monitoria de origem.",
            ),
            _labeled("ID do Incidente (SLA)", display_value(incident_id)),
        ]
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
        f"🟢 *STATUS DO MONITOR* ({clock_str})\n"
        f"Nagstamon Headless ativo e operacional. "
        f"{servers_count} servidores monitorados com sucesso, "
        "0 incidentes pendentes."
    )
