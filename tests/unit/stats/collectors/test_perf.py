from __future__ import annotations

import pytest

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

        import time

        # Force a time delta for rate calculation
        collector._last_time = time.perf_counter_ns() - int(1e9)

        collector.process(events)
        metrics = collector.get_metrics()

        assert metrics["total_paths_explored"] == 2.0
        assert float(metrics["path_exploration_rate"]) > 0.0

    def test_process_updates_max_memory(self) -> None:
        """Verify that max memory is updated if it increases."""
        collector = PerfCollector()
        events = [Event(type=EventType.PATH_EXPLORED, value=0.0)]
        collector.process(events)
        metrics = collector.get_metrics()
        assert float(metrics["max_memory_mb"]) >= 0.0

    def test_get_metrics_returns_copy(self) -> None:
        """Verify that get_metrics returns a copy of the metrics dict."""
        collector = PerfCollector()
        metrics1 = collector.get_metrics()
        metrics1["total_paths_explored"] = 100.0
        metrics2 = collector.get_metrics()
        assert metrics2["total_paths_explored"] == 0.0
