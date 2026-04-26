import threading
import time
from typing import Any
import pytest

from pysymex.stats.registry import StatsRegistry
from pysymex.stats.collectors.base import MetricCollector
from pysymex.stats.sinks.base import StatsSink
from pysymex.stats.types import Event, EventType


class MockCollector(MetricCollector):
    def __init__(self):
        self.processed_events = []
        self.metrics = {"mock_metric": 42.0}

    def process(self, events: list[Event]) -> None:
        self.processed_events.extend(events)

    def get_metrics(self) -> dict[str, float | int | str]:
        return self.metrics


class MockSink(StatsSink):
    def __init__(self, raise_error=False):
        self.written_metrics = {}
        self.raise_error = raise_error

    def write(self, metrics: dict[str, float | int | str]) -> None:
        if self.raise_error:
            raise RuntimeError("Mock sink write error")
        self.written_metrics.update(metrics)


@pytest.fixture
def clean_registry():
    """Reset the StatsRegistry singleton instance and stop any running thread before and after each test."""

    def cleanup():
        with StatsRegistry._lock:
            if StatsRegistry._instance is not None:
                if StatsRegistry._instance._running:
                    StatsRegistry._instance.stop()
                StatsRegistry._instance = None

    cleanup()
    yield
    cleanup()


def test_singleton(clean_registry):
    """Verify that multiple instantiations return the same object."""
    r1 = StatsRegistry()
    r2 = StatsRegistry()
    assert r1 is r2


def test_register_collector_and_sink(clean_registry):
    """Verify registration adds collectors and sinks and fetches initial metrics."""
    registry = StatsRegistry()
    collector = MockCollector()
    sink = MockSink()

    registry.register_collector(collector)
    assert collector in registry._collectors
    assert registry._global_metrics["mock_metric"] == 42.0

    registry.register_sink(sink)
    assert sink in registry._sinks


def test_emit(clean_registry):
    """Verify emit appends events to thread-local buffer."""
    registry = StatsRegistry()
    registry.emit(EventType.PATH_EXPLORED, 1.0, {"meta": "data"})

    buffer = registry._get_buffer()
    assert len(buffer) == 1

    event = buffer[0]
    assert event.type == EventType.PATH_EXPLORED
    assert event.value == 1.0
    assert event.metadata == {"meta": "data"}


def test_flush(clean_registry):
    """Verify flush empties buffers and correctly delegates to collectors and sinks."""
    registry = StatsRegistry()
    collector = MockCollector()
    sink_success = MockSink(raise_error=False)
    sink_fail = MockSink(raise_error=True)

    registry.register_collector(collector)
    registry.register_sink(sink_fail)
    registry.register_sink(sink_success)

    registry.emit(EventType.PATH_EXPLORED, 1.0)
    registry.emit(EventType.SOLVER_QUERY, 2.0)

    registry.flush()

    buffer = registry._get_buffer()
    assert len(buffer) == 0

    assert len(collector.processed_events) == 2
    assert collector.processed_events[0].type == EventType.PATH_EXPLORED
    assert collector.processed_events[1].type == EventType.SOLVER_QUERY

    assert sink_success.written_metrics["mock_metric"] == 42.0


def test_start_stop(clean_registry):
    """Verify start initializes flusher thread and stop joins it and flushes one last time."""
    registry = StatsRegistry()
    collector = MockCollector()
    sink = MockSink()
    registry.register_collector(collector)
    registry.register_sink(sink)

    registry.start()
    assert registry._running is True
    assert registry._flusher_thread is not None
    assert registry._flusher_thread.is_alive()

    registry.emit(EventType.PATH_EXPLORED, 1.0)

    registry.stop()
    assert registry._running is False
    assert not registry._flusher_thread.is_alive()

    assert len(collector.processed_events) == 1
    assert sink.written_metrics["mock_metric"] == 42.0


def test_multithreaded_emit(clean_registry):
    """Verify thread-safety of emit across multiple threads without lock contention."""
    registry = StatsRegistry()
    collector = MockCollector()
    registry.register_collector(collector)

    num_threads = 10
    emits_per_thread = 100

    def emit_events():
        for i in range(emits_per_thread):
            registry.emit(EventType.PATH_EXPLORED, float(i))

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=emit_events)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    registry.flush()

    assert len(collector.processed_events) == num_threads * emits_per_thread
