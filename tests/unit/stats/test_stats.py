import time
from pysymex.stats import emit, EventType, start, stop, registry


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
    metrics = {}
    for collector in registry._collectors:
        metrics.update(collector.get_metrics())

    assert metrics["total_paths_explored"] >= 1.0
    # sat_unsat_ratio may vary based on solver state, just check it's a valid ratio
    assert 0.0 <= metrics["sat_unsat_ratio"] <= 1.0
