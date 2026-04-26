from __future__ import annotations

from pysymex.stats.collectors.smt import SmtCollector
from pysymex.stats.types import Event, EventType


class TestSmtCollector:
    """Test suite for stats/collectors/smt.py."""

    def test_initialization(self) -> None:
        """Verify that SmtCollector initializes with zero sat_unsat_ratio."""
        collector = SmtCollector()
        metrics = collector.get_metrics()
        assert metrics["sat_unsat_ratio"] == 0.0

    def test_process_sat_unsat_unknown(self) -> None:
        """Verify that SAT, UNSAT, UNKNOWN events are processed."""
        collector = SmtCollector()
        events = [
            Event(type=EventType.SOLVER_SAT, value=0.0),
            Event(type=EventType.SOLVER_SAT, value=0.0),
            Event(type=EventType.SOLVER_UNSAT, value=0.0),
            Event(type=EventType.SOLVER_UNKNOWN, value=0.0),
        ]
        collector.process(events)
        assert collector._sat_count == 2
        assert collector._unsat_count == 1
        assert collector._unknown_count == 1

    def test_process_query_int_clauses(self) -> None:
        """Verify that SOLVER_QUERY with int clauses updates total clauses."""
        collector = SmtCollector()
        events = [Event(type=EventType.SOLVER_QUERY, value=0.0, metadata={"clauses": 5})]
        collector.process(events)
        assert collector._total_clauses == 5

    def test_process_query_float_clauses(self) -> None:
        """Verify that SOLVER_QUERY with float clauses updates total clauses."""
        collector = SmtCollector()
        events = [Event(type=EventType.SOLVER_QUERY, value=0.0, metadata={"clauses": 3.14})]
        collector.process(events)
        assert collector._total_clauses == 3

    def test_get_metrics_ratio_gt_zero(self) -> None:
        """Verify that sat_unsat_ratio is correctly computed."""
        collector = SmtCollector()
        events = [
            Event(type=EventType.SOLVER_SAT, value=0.0),
            Event(type=EventType.SOLVER_UNSAT, value=0.0),
            Event(type=EventType.SOLVER_UNSAT, value=0.0),
            Event(type=EventType.SOLVER_UNSAT, value=0.0),
        ]
        collector.process(events)
        metrics = collector.get_metrics()
        assert metrics["sat_unsat_ratio"] == 0.25

    def test_get_metrics_ratio_zero_queries(self) -> None:
        """Verify that sat_unsat_ratio is 0.0 when no queries are processed."""
        collector = SmtCollector()
        metrics = collector.get_metrics()
        assert metrics["sat_unsat_ratio"] == 0.0
