import os
import threading
from collections.abc import Generator

import pytest

from pysymex.stats.collectors.base import MetricCollector
from pysymex.stats.registry import StatsRegistry
from pysymex.stats.sinks.base import StatsSink
from pysymex.stats.types import Event, EventType

MetricValue = float | int | str
pytestmark = pytest.mark.usefixtures("clean_registry")


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
        with StatsRegistry.lock:
            if StatsRegistry.instance is not None:
                if StatsRegistry.instance.running:
                    StatsRegistry.instance.stop()
                StatsRegistry.instance = None

    cleanup()
    yield
    cleanup()


def test_singleton() -> None:
    """Verify that multiple instantiations return the same object."""
    r1 = StatsRegistry()
    r2 = StatsRegistry()
    assert r1 is r2


def test_register_collector_and_sink() -> None:
    """Verify registration adds collectors and sinks and fetches initial metrics."""
    registry = StatsRegistry()
    collector = MockCollector()
    sink = MockSink()

    registry.register_collector(collector)
    assert collector in registry.collectors
    assert registry.global_metrics["mock_metric"] == 42.0

    registry.register_sink(sink)
    assert sink in registry.sinks


def test_emit() -> None:
    """Verify emit appends events to thread-local buffer."""
    registry = StatsRegistry()
    registry.emit(EventType.PATH_EXPLORED, 1.0, {"meta": "data"})

    buffer = registry.get_buffer()
    assert len(buffer) == 1

    event = buffer[0]
    assert event.type == EventType.PATH_EXPLORED
    assert event.value == 1.0
    assert event.metadata == {"meta": "data"}


def test_hot_solver_event_helper_noops_when_stats_stopped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Solver hot-path telemetry should not allocate events unless stats is running."""
    from pysymex.core.solver.engine import events as solver_events

    registry = StatsRegistry()
    monkeypatch.setattr(solver_events, "_stats_registry", registry)

    solver_events.emit_event(EventType.SOLVER_QUERY, 1.0)

    assert len(registry.get_buffer()) == 0


def test_hot_executor_event_helper_noops_when_stats_stopped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Executor hot-path telemetry should not allocate path events unless stats is running."""
    from pysymex.execution.executors.executor import events as executor_events

    registry = StatsRegistry()
    monkeypatch.setattr(executor_events, "_stats_registry", registry)

    executor_events.emit_event(EventType.PATH_EXPLORED, 1.0)

    assert len(registry.get_buffer()) == 0


def test_flush() -> None:
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

    buffer = registry.get_buffer()
    assert len(buffer) == 0

    assert len(collector.processed_events) == 2
    assert collector.processed_events[0].type == EventType.PATH_EXPLORED
    assert collector.processed_events[1].type == EventType.SOLVER_QUERY

    assert sink_success.written_metrics["mock_metric"] == 42.0


def test_start_stop(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify start initializes flusher thread and stop joins it and flushes one last time."""
    monkeypatch.setattr(os, "name", "posix")
    registry = StatsRegistry()
    collector = MockCollector()
    sink = MockSink()
    registry.register_collector(collector)
    registry.register_sink(sink)

    registry.start()
    assert registry.running is True
    assert registry.flusher_thread is not None
    assert registry.flusher_thread.is_alive()

    registry.emit(EventType.PATH_EXPLORED, 1.0)

    flusher_thread = registry.flusher_thread
    registry.stop()
    assert registry.running is False
    assert not flusher_thread.is_alive()

    assert len(collector.processed_events) == 1
    assert sink.written_metrics["mock_metric"] == 42.0


def test_windows_start_uses_inline_flush(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify Windows stats stream without a parallel flusher thread."""
    monkeypatch.setattr(os, "name", "nt")
    registry = StatsRegistry()
    collector = MockCollector()
    sink = MockSink()
    registry.register_collector(collector)
    registry.register_sink(sink)

    registry.start()
    assert registry.running is True
    assert registry.flusher_thread is None

    registry.emit(EventType.PATH_EXPLORED, 1.0)

    assert len(collector.processed_events) == 1
    assert sink.written_metrics["mock_metric"] == 42.0
    registry.stop()


def test_start_clears_stale_buffers_and_resets_collectors(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify a stats run starts from a clean collection window."""
    monkeypatch.setattr(os, "name", "nt")

    class ResettableCollector(MockCollector):
        def reset(self) -> None:
            self.processed_events.clear()
            self.metrics = {"mock_metric": 0.0}

        def process(self, events: list[Event]) -> None:
            super().process(events)
            self.metrics = {"mock_metric": float(len(self.processed_events))}

    registry = StatsRegistry()
    collector = ResettableCollector()
    registry.register_collector(collector)

    registry.emit(EventType.PATH_EXPLORED, 99.0)
    assert len(registry.get_buffer()) == 1

    registry.start()
    assert len(registry.get_buffer()) == 0
    assert registry.global_metrics["mock_metric"] == 0.0

    registry.emit(EventType.PATH_EXPLORED, 1.0)
    registry.stop()

    assert [event.value for event in collector.processed_events] == [1.0]
    assert registry.global_metrics["mock_metric"] == 1.0


def test_multithreaded_emit() -> None:
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
