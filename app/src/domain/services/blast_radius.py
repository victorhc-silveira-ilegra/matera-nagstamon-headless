from __future__ import annotations

from collections.abc import Sequence

from domain.entities.alert import Alert
from domain.entities.severity import Severity


def correlate_blast_radius(
    alerts: Sequence[Alert],
    threshold: int = 5,
) -> list[Alert]:
    if threshold <= 1 or not alerts:
        return list(alerts)
    by_node: dict[tuple[str, str], list[Alert]] = {}
    ungrouped: list[Alert] = []
    for alert in alerts:
        node = alert.host.strip()
        if not node or node.lower() == "n/a":
            ungrouped.append(alert)
            continue
        key = (alert.server, node)
        by_node.setdefault(key, []).append(alert)
    result: list[Alert] = list(ungrouped)
    for (server, node), group in by_node.items():
        if len(group) < threshold:
            result.extend(group)
            continue
        count = len(group)
        services = sorted({a.alertname for a in group})
        summary_services = ", ".join(services[:5])
        if len(services) > 5:
            summary_services += f" (+{len(services) - 5} outros)"
        status_text = (
            f"Falha simultanea de {count} servicos no host {node}: {summary_services}"
        )
        valid_starts = [a.starts_at for a in group if a.starts_at is not None]
        starts_at = min(valid_starts) if valid_starts else None
        env = next((a.environment for a in group if a.environment), "")
        consolidated = Alert(
            server=server,
            severity=Severity("CRITICAL"),
            alertname="BlastRadiusDetected",
            app="Infrastructure",
            desc=f"Blast radius: {count} incidentes simultaneos no host {node}",
            status_text=status_text,
            starts_at=starts_at,
            host=node,
            environment=env,
            notifications_enabled=True,
            in_maintenance=False,
            is_soft_state=False,
            checks_enabled=True,
        )
        result.append(consolidated)
    return result
