from __future__ import annotations

import pytest

from pysymex.stats.collectors.base import MetricCollector
from pysymex.stats.types import Event


class MockCollector(MetricCollector):
    """Mock collector to test base methods."""

    def process(self, events: list[Event]) -> None:
        super().process(events)

    def get_metrics(self) -> dict[str, float | int | str]:
        super().get_metrics()
        return {}


class TestMetricCollector:
    """Test suite for stats/collectors/base.py."""

    def test_process_raises_runtime_error(self) -> None:
        """Verify that MetricCollector.process raises RuntimeError."""
        collector = MockCollector()
        with pytest.raises(
            RuntimeError, match="MetricCollector.process must be implemented by subclasses"
        ):
            collector.process([])

    def test_get_metrics_raises_runtime_error(self) -> None:
        """Verify that MetricCollector.get_metrics raises RuntimeError."""
        collector = MockCollector()
        with pytest.raises(
            RuntimeError, match="MetricCollector.get_metrics must be implemented by subclasses"
        ):
            collector.get_metrics()
