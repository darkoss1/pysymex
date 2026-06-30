from __future__ import annotations

from pysymex._internal.stats.collectors.smt import SmtCollector
from pysymex._internal.stats.types import Event, EventType


class TestSmtCollector:
    """Test suite for stats/collectors/smt.py."""

    def test_initialization(self) -> None:
        """Verify that SmtCollector initializes solver counters."""
        collector = SmtCollector()
        metrics = collector.get_metrics()
        assert metrics["solver_queries"] == 0
        assert metrics["solver_unknown"] == 0

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
        assert collector.sat_count == 2
        assert collector.unsat_count == 1
        assert collector.unknown_count == 1
        metrics = collector.get_metrics()
        assert metrics["solver_sat"] == 2
        assert metrics["solver_unsat"] == 1
        assert metrics["solver_unknown"] == 1

    def test_process_aggregate_solver_counts(self) -> None:
        """Verify aggregate scan-published solver events preserve exact totals."""
        collector = SmtCollector()
        events = [
            Event(type=EventType.SOLVER_QUERY, value=7.0),
            Event(type=EventType.SOLVER_SAT, value=3.0),
            Event(type=EventType.SOLVER_UNSAT, value=2.0),
            Event(type=EventType.SOLVER_UNKNOWN, value=2.0),
        ]

        collector.process(events)

        metrics = collector.get_metrics()
        assert metrics["solver_queries"] == 7
        assert metrics["solver_sat"] == 3
        assert metrics["solver_unsat"] == 2
        assert metrics["solver_unknown"] == 2

    def test_process_query_int_clauses(self) -> None:
        """Verify that SOLVER_QUERY with int clauses updates total clauses."""
        collector = SmtCollector()
        events = [Event(type=EventType.SOLVER_QUERY, value=0.0, metadata={"clauses": 5})]
        collector.process(events)
        assert collector.total_clauses == 5
        metrics = collector.get_metrics()
        assert metrics["solver_queries"] == 1
        assert metrics["solver_total_clauses"] == 5
        assert metrics["solver_avg_clauses"] == 5.0

    def test_process_query_float_clauses(self) -> None:
        """Verify that SOLVER_QUERY with float clauses updates total clauses."""
        collector = SmtCollector()
        events = [Event(type=EventType.SOLVER_QUERY, value=0.0, metadata={"clauses": 3.14})]
        collector.process(events)
        assert collector.total_clauses == 3

    def test_boolean_clause_metadata_is_not_counted_as_int(self) -> None:
        """Verify bool metadata does not corrupt clause totals."""
        collector = SmtCollector()
        events = [Event(type=EventType.SOLVER_QUERY, value=0.0, metadata={"clauses": True})]
        collector.process(events)
        metrics = collector.get_metrics()
        assert metrics["solver_queries"] == 1
        assert metrics["solver_total_clauses"] == 0
        assert metrics["solver_avg_clauses"] == 0.0

    def test_reset_clears_previous_solver_metrics(self) -> None:
        """Verify repeated stats runs do not retain previous solver counters."""
        collector = SmtCollector()
        collector.process(
            [
                Event(type=EventType.SOLVER_QUERY, value=0.0, metadata={"clauses": 4}),
                Event(type=EventType.SOLVER_UNKNOWN, value=1.0),
            ]
        )

        collector.reset()

        metrics = collector.get_metrics()
        assert metrics["solver_queries"] == 0
        assert metrics["solver_unknown"] == 0
        assert metrics["solver_total_clauses"] == 0
