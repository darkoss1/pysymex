import os
import threading
from collections.abc import Generator

import pytest

from pysymex.stats.collectors.base import MetricCollector
from pysymex.stats.registry import StatsRegistry
from pysymex.stats.sinks.base import StatsSink
from pysymex.stats.types import Event, EventType

MetricValue = float | int | str


class MockCollector(MetricCollector):
    def __init__(self) -> None:
        self.processed_events: list[Event] = []
        self.metrics: dict[str, MetricValue] = {"mock_metric": 42.0}

    def process(self, events: list[Event]) -> None:
        self.processed_events.extend(events)

    def get_metrics(self) -> dict[str, MetricValue]:
        return self.metrics


class MockSink(StatsSink):
    def __init__(self, raise_error: bool = False) -> None:
        self.written_metrics: dict[str, MetricValue] = {}
        self.raise_error = raise_error

    def write(self, metrics: dict[str, MetricValue]) -> None:
        if self.raise_error:
            raise RuntimeError("Mock sink write error")
        self.written_metrics.update(metrics)


@pytest.fixture
def clean_registry() -> Generator[None]:
    """Reset the StatsRegistry singleton instance and stop any running thread before and after each test."""

    def cleanup() -> None:
        with StatsRegistry._lock:  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
            if StatsRegistry._instance is not None:  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
                if StatsRegistry._instance._running:  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
                    StatsRegistry._instance.stop()  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
                StatsRegistry._instance = None  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state

    cleanup()
    yield
    cleanup()


def test_singleton(clean_registry: None) -> None:
    """Verify that multiple instantiations return the same object."""
    r1 = StatsRegistry()
    r2 = StatsRegistry()
    assert r1 is r2


def test_register_collector_and_sink(clean_registry: None) -> None:
    """Verify registration adds collectors and sinks and fetches initial metrics."""
    registry = StatsRegistry()
    collector = MockCollector()
    sink = MockSink()

    registry.register_collector(collector)
    assert collector in registry._collectors  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
    assert registry._global_metrics["mock_metric"] == 42.0  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state

    registry.register_sink(sink)
    assert sink in registry._sinks  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state


def test_emit(clean_registry: None) -> None:
    """Verify emit appends events to thread-local buffer."""
    registry = StatsRegistry()
    registry.emit(EventType.PATH_EXPLORED, 1.0, {"meta": "data"})

    buffer = registry._get_buffer()  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
    assert len(buffer) == 1

    event = buffer[0]
    assert event.type == EventType.PATH_EXPLORED
    assert event.value == 1.0
    assert event.metadata == {"meta": "data"}


def test_flush(clean_registry: None) -> None:
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

    buffer = registry._get_buffer()  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
    assert len(buffer) == 0

    assert len(collector.processed_events) == 2
    assert collector.processed_events[0].type == EventType.PATH_EXPLORED
    assert collector.processed_events[1].type == EventType.SOLVER_QUERY

    assert sink_success.written_metrics["mock_metric"] == 42.0


def test_start_stop(clean_registry: None, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify start initializes flusher thread and stop joins it and flushes one last time."""
    monkeypatch.setattr(os, "name", "posix")
    registry = StatsRegistry()
    collector = MockCollector()
    sink = MockSink()
    registry.register_collector(collector)
    registry.register_sink(sink)

    registry.start()
    assert registry._running is True  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
    assert registry._flusher_thread is not None  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
    assert registry._flusher_thread.is_alive()  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state

    registry.emit(EventType.PATH_EXPLORED, 1.0)

    flusher_thread = registry._flusher_thread  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
    registry.stop()
    assert registry._running is False  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
    assert not flusher_thread.is_alive()  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state

    assert len(collector.processed_events) == 1
    assert sink.written_metrics["mock_metric"] == 42.0


def test_windows_start_uses_inline_flush(
    clean_registry: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify Windows stats stream without a parallel flusher thread."""
    monkeypatch.setattr(os, "name", "nt")
    registry = StatsRegistry()
    collector = MockCollector()
    sink = MockSink()
    registry.register_collector(collector)
    registry.register_sink(sink)

    registry.start()
    assert registry._running is True  # type: ignore[reportPrivateUsage]  # white-box test validates Windows flusher policy
    assert registry._flusher_thread is None  # type: ignore[reportPrivateUsage]  # white-box test validates Windows flusher policy

    registry.emit(EventType.PATH_EXPLORED, 1.0)

    assert len(collector.processed_events) == 1
    assert sink.written_metrics["mock_metric"] == 42.0
    registry.stop()


def test_multithreaded_emit(clean_registry: None) -> None:
    """Verify thread-safety of emit across multiple threads without lock contention."""
    registry = StatsRegistry()
    collector = MockCollector()
    registry.register_collector(collector)

    num_threads = 10
    emits_per_thread = 100

    def emit_events() -> None:
        for i in range(emits_per_thread):
            registry.emit(EventType.PATH_EXPLORED, float(i))

    threads: list[threading.Thread] = []
    for _ in range(num_threads):
        t = threading.Thread(target=emit_events)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    registry.flush()

    assert len(collector.processed_events) == num_threads * emits_per_thread
