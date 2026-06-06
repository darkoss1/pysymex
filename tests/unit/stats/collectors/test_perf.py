from __future__ import annotations

import time

from pysymex.stats.collectors.perf import PerfCollector
from pysymex.stats.types import Event, EventType


class TestPerfCollector:
    """Test suite for stats/collectors/perf.py."""

    def test_initialization(self) -> None:
        """Verify that PerfCollector initializes with zero metrics."""
        collector = PerfCollector()
        metrics = collector.get_metrics()
        assert metrics["path_exploration_rate"] == 0.0
        assert metrics["total_paths_explored"] == 0.0
        assert metrics["max_memory_mb"] == 0.0

    def test_process_no_path_explored_events(self) -> None:
        """Verify that processing non-PATH_EXPLORED events updates only memory/time, not paths."""
        collector = PerfCollector()
        events = [Event(type=EventType.SOLVER_SAT, value=0.0)]
        collector.process(events)
        metrics = collector.get_metrics()
        assert metrics["total_paths_explored"] == 0.0

    def test_process_path_explored_events(self) -> None:
        """Verify that processing PATH_EXPLORED events updates path counts and rate."""
        collector = PerfCollector()
        events = [
            Event(type=EventType.PATH_EXPLORED, value=0.0),
            Event(type=EventType.PATH_EXPLORED, value=0.0),
        ]

        # Force a time delta for rate calculation
        collector.last_rate_timestamp_ns = time.perf_counter_ns() - int(1e9)

        collector.process(events)
        metrics = collector.get_metrics()

        assert metrics["total_paths_explored"] == 2.0
        assert float(metrics["path_exploration_rate"]) > 0.0

    def test_average_path_rate_uses_collection_elapsed_time(self) -> None:
        """Verify final aggregate path events cannot inflate average throughput."""
        collector = PerfCollector()
        start_ns = time.perf_counter_ns() - int(2e9)
        setattr(collector, "_start_time", start_ns)
        collector.last_rate_timestamp_ns = start_ns

        collector.process([Event(type=EventType.PATH_EXPLORED, value=2.0)])

        metrics = collector.get_metrics()
        avg_rate = float(metrics["path_exploration_rate_avg"])
        assert 0.9 <= avg_rate <= 1.1

    def test_process_updates_max_memory(self) -> None:
        """Verify that max memory is updated if it increases."""
        collector = PerfCollector()
        events = [Event(type=EventType.PATH_EXPLORED, value=0.0)]
        collector.process(events)
        metrics = collector.get_metrics()
        assert float(metrics["max_memory_mb"]) >= 0.0

    def test_process_memory_sample_event_uses_reported_value(self) -> None:
        """Verify explicit scan memory samples are reflected in reported metrics."""
        collector = PerfCollector()
        events = [Event(type=EventType.MEMORY_SAMPLE, value=123.5)]
        collector.process(events)
        metrics = collector.get_metrics()
        assert metrics["max_memory_mb"] == 123.5
        assert metrics["avg_memory_mb"] == 123.5

    def test_scan_average_memory_replaces_only_final_average(self) -> None:
        """Verify final scan-average memory matches scan summaries without lowering peak."""
        collector = PerfCollector()

        collector.process(
            [
                Event(type=EventType.MEMORY_SAMPLE, value=50.0),
                Event(type=EventType.MEMORY_SAMPLE, value=150.0),
            ]
        )
        collector.process([Event(type=EventType.SCAN_AVG_MEMORY, value=80.0)])

        metrics = collector.get_metrics()
        assert metrics["max_memory_mb"] == 150.0
        assert metrics["avg_memory_mb"] == 80.0

    def test_get_metrics_returns_copy(self) -> None:
        """Verify that get_metrics returns a copy of the metrics dict."""
        collector = PerfCollector()
        metrics1 = collector.get_metrics()
        metrics1["total_paths_explored"] = 100.0
        metrics2 = collector.get_metrics()
        assert metrics2["total_paths_explored"] == 0.0

    def test_reset_clears_previous_scan_metrics(self) -> None:
        """Verify repeated stats runs do not retain previous counters."""
        collector = PerfCollector()
        collector.process([Event(type=EventType.PATH_EXPLORED, value=2.0)])

        collector.reset()

        metrics = collector.get_metrics()
        assert metrics["total_paths_explored"] == 0.0
        assert metrics["path_exploration_rate_avg"] == 0.0
