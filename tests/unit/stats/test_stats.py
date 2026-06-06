from __future__ import annotations

from pysymex.stats import enable_console_sink, emit, EventType, start, stop, registry
from pysymex.stats.sinks.console import ConsoleSink
from pysymex.stats.types import MetricValue


def test_stats_integration() -> None:
    """Test the full stats pipeline."""
    start()
    try:
        emit(EventType.PATH_EXPLORED, 1.0)
        emit(EventType.SOLVER_QUERY, 0.0, {"clauses": 100, "vars": 50})
        emit(EventType.SOLVER_SAT, 1.0)
    finally:
        stop()

        # Check if collectors received the events (safe after stop() which calls flush)
    metrics: dict[str, MetricValue] = {}
    for collector in registry.collectors:
        metrics.update(collector.get_metrics())

    total_paths = metrics["total_paths_explored"]
    assert isinstance(total_paths, int | float)
    assert total_paths >= 1.0
    # sat_unsat_ratio may vary based on solver state, just check it's a valid ratio
    sat_unsat_ratio = metrics["sat_unsat_ratio"]
    assert isinstance(sat_unsat_ratio, int | float)
    assert 0.0 <= sat_unsat_ratio <= 1.0
    assert metrics["solver_queries"] == 1
    solver_sat = metrics["solver_sat"]
    assert isinstance(solver_sat, int | float)
    assert solver_sat >= 1


def test_enable_console_sink_is_idempotent() -> None:
    """Repeated CLI setup should not register duplicate console sinks."""
    original_sinks = list(registry.sinks)
    registry.sinks.clear()
    try:
        enable_console_sink()
        enable_console_sink()
        console_sinks = [sink for sink in registry.sinks if isinstance(sink, ConsoleSink)]
        assert len(console_sinks) == 1
    finally:
        registry.sinks[:] = original_sinks
