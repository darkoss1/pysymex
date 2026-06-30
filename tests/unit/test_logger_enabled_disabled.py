from __future__ import annotations

from collections.abc import Iterator, Mapping
from io import StringIO
from unittest.mock import patch

from pysymex._internal.logging.categories import LogCategory
from pysymex._internal.logging.entry import LogEntry
from pysymex._internal.logging.levels import LogLevel
from pysymex._internal.logging.logger import PysymexLogger


class RecordingSink:
    """Test sink that records enabled entries."""

    def __init__(self) -> None:
        self.entries: list[LogEntry] = []

    def emit(self, entry: LogEntry) -> None:
        self.entries.append(entry)


class FailingMetadata(Mapping[str, object]):
    """Mapping that fails if disabled logging tries to inspect metadata."""

    def __getitem__(self, key: str) -> object:
        raise AssertionError(f"metadata key {key} should not be read")

    def __iter__(self) -> Iterator[str]:
        raise AssertionError("metadata should not be iterated")

    def __len__(self) -> int:
        raise AssertionError("metadata should not be measured")


def test_level_matrix_dispatches_only_enabled_events() -> None:
    """Normal/debug/trace levels should dispatch exactly the enabled severities."""
    normal_sink = RecordingSink()
    normal = PysymexLogger(level=LogLevel.NORMAL, stream=StringIO(), color=False)
    normal.state.sinks.append(normal_sink)
    normal.debug("debug")
    normal.trace("trace")
    normal.info("info")
    assert [entry.message for entry in normal_sink.entries] == ["info"]

    debug_sink = RecordingSink()
    debug = PysymexLogger(level=LogLevel.DEBUG, stream=StringIO(), color=False)
    debug.state.sinks.append(debug_sink)
    debug.debug("debug")
    debug.trace("trace")
    assert [entry.message for entry in debug_sink.entries] == ["debug"]

    trace_sink = RecordingSink()
    trace = PysymexLogger(level=LogLevel.TRACE, stream=StringIO(), color=False)
    trace.state.sinks.append(trace_sink)
    trace.debug("debug")
    trace.trace("trace")
    assert [entry.message for entry in trace_sink.entries] == ["debug", "trace"]


def test_category_disabled_event_does_not_resolve_message_metadata_timestamp_or_sink() -> None:
    """Disabled categories should return before enabled-event work starts."""
    sink = RecordingSink()
    logger = PysymexLogger(
        level=LogLevel.TRACE,
        stream=StringIO(),
        color=False,
        categories={LogCategory.SOLVER},
    )
    logger.state.sinks.append(sink)

    def fail_message() -> str:
        raise AssertionError("message should not be resolved")

    with (
        patch("pysymex._internal.logging.emit.time.time") as timestamp,
        patch("pysymex._internal.logging.emit.LogEntry") as log_entry,
    ):
        logger.trace(fail_message, category=LogCategory.OPCODE, metadata=FailingMetadata())

    timestamp.assert_not_called()
    log_entry.assert_not_called()
    assert sink.entries == []


def test_enabled_structured_event_preserves_metadata_and_source() -> None:
    """Enabled structured events should retain metadata and source fields."""
    sink = RecordingSink()
    logger = PysymexLogger(
        level=LogLevel.DEBUG,
        stream=StringIO(),
        color=False,
        categories={LogCategory.SOLVER},
    )
    logger.state.sinks.append(sink)

    logger.log(
        LogLevel.DEBUG,
        "solver result %s",
        "sat",
        category=LogCategory.SOLVER,
        event_name="solver.check",
        source_module="pysymex._internal.core.solver.engine",
        metadata={"path_id": 7, "elapsed_ms": 3.5},
    )

    assert len(sink.entries) == 1
    entry = sink.entries[0]
    assert entry.message == "solver result sat"
    assert entry.category == "solver"
    assert entry.event_name == "solver.check"
    assert entry.source_module == "pysymex._internal.core.solver.engine"
    assert entry.metadata == {"path_id": 7, "elapsed_ms": 3.5}
    assert entry.timestamp > 0.0


def test_disabled_timer_does_not_capture_perf_counter_or_emit() -> None:
    """A disabled timer should avoid perf_counter and sink dispatch."""
    sink = RecordingSink()
    logger = PysymexLogger(level=LogLevel.NORMAL, stream=StringIO(), color=False)
    logger.state.sinks.append(sink)

    with patch("pysymex._internal.logging.console.time.perf_counter") as perf_counter:
        with logger.timer("disabled"):
            pass

    perf_counter.assert_not_called()
    assert sink.entries == []


def test_enabled_timer_emits_elapsed_verbose_event() -> None:
    """An enabled timer should capture elapsed time and emit one verbose event."""
    sink = RecordingSink()
    logger = PysymexLogger(level=LogLevel.VERBOSE, stream=StringIO(), color=False)
    logger.state.sinks.append(sink)

    with patch("pysymex._internal.logging.console.time.perf_counter", side_effect=[10.0, 10.125]):
        with logger.timer("enabled", category="performance"):
            pass

    assert len(sink.entries) == 1
    assert sink.entries[0].level == LogLevel.VERBOSE
    assert sink.entries[0].category == "performance"
    assert sink.entries[0].message == "enabled: 0.125s"


def test_enabled_exception_captures_raw_exception_for_sinks() -> None:
    """Enabled exception logs should pass raw exception data to sinks."""
    sink = RecordingSink()
    logger = PysymexLogger(level=LogLevel.NORMAL, stream=StringIO(), color=False)
    logger.state.sinks.append(sink)

    try:
        raise RuntimeError("enabled failure")
    except RuntimeError:
        logger.exception("failed")

    assert len(sink.entries) == 1
    entry = sink.entries[0]
    assert entry.exception is not None
    assert entry.exception.exc_type is RuntimeError
    assert str(entry.exception.exc_value) == "enabled failure"
