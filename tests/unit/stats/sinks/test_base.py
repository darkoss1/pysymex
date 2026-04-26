from __future__ import annotations

import pytest

from pysymex.stats.sinks.base import StatsSink


class MockSink(StatsSink):
    """Mock sink to test base methods."""

    def write(self, metrics: dict[str, float | int | str]) -> None:
        super().write(metrics)


class TestStatsSink:
    """Test suite for stats/sinks/base.py."""

    def test_write_raises_runtime_error(self) -> None:
        """Verify that StatsSink.write raises RuntimeError."""
        sink = MockSink()
        with pytest.raises(RuntimeError, match="StatsSink.write must be implemented by subclasses"):
            sink.write({})
