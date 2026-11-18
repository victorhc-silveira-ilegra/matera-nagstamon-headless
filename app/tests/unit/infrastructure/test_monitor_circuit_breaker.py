from __future__ import annotations

from datetime import UTC, datetime, timedelta

from infrastructure.adapters.monitor_circuit_breaker import MonitorCircuitBreaker

NOW = datetime(2026, 8, 14, 17, 0, 0, tzinfo=UTC)


def test_circuit_breaker_flow() -> None:
    breaker = MonitorCircuitBreaker(max_failures=3, cooldown_seconds=300)
    assert breaker.is_available("srv1", NOW)

    breaker.record_failure("srv1", NOW)
    assert breaker.is_available("srv1", NOW)
    breaker.record_failure("srv1", NOW)
    assert breaker.is_available("srv1", NOW)

    breaker.record_failure("srv1", NOW)
    assert not breaker.is_available("srv1", NOW)
    assert not breaker.is_available("srv1", NOW + timedelta(seconds=299))

    assert breaker.is_available("srv1", NOW + timedelta(seconds=301))
    assert breaker.is_available("srv1", NOW + timedelta(seconds=301))

    breaker.record_failure("srv1", NOW)
    breaker.record_failure("srv1", NOW)
    breaker.record_failure("srv1", NOW)
    assert not breaker.is_available("srv1", NOW)

    breaker.record_success("srv1")
    assert breaker.is_available("srv1", NOW)
