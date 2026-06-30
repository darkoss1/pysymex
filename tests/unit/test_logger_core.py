import time
from collections.abc import Iterator, Mapping
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from pysymex._internal.logging.categories import LogCategory
from pysymex._internal.logging.levels import LogLevel
from pysymex._internal.logging.logger import PysymexLogger
from pysymex._internal.logging.root import configure_logging, get_logger, reset_logging


class ExplodingMetadata(Mapping[str, object]):
    """Mapping that fails if the logger inspects it."""

    def __getitem__(self, key: str) -> object:
        raise AssertionError(f"metadata key {key} should not be read")

    def __iter__(self) -> Iterator[str]:
        raise AssertionError("metadata should not be inspected")

    def __len__(self) -> int:
        raise AssertionError("metadata should not be measured")


class TestPysymexLogger:
    """Test suite for pysymex._internal.logging.PysymexLogger."""

    def test_set_level(self) -> None:
        """Test set_level behavior."""
        logger = PysymexLogger(level=LogLevel.NORMAL)
        logger.set_level(LogLevel.DEBUG)
        assert logger.level == LogLevel.DEBUG

    def test_log(self) -> None:
        """Test log behavior."""
        stream = StringIO()
        logger = PysymexLogger(level=LogLevel.NORMAL, stream=stream, color=False)
        logger.log(LogLevel.NORMAL, "test log")
        assert "test log" in stream.getvalue()

    def test_info(self) -> None:
        """Test info behavior."""
        stream = StringIO()
        logger = PysymexLogger(level=LogLevel.NORMAL, stream=stream, color=False)
        logger.info("test info")
        assert "test info" in stream.getvalue()

    def test_verbose(self) -> None:
        """Test verbose behavior."""
        stream = StringIO()
        logger = PysymexLogger(level=LogLevel.VERBOSE, stream=stream, color=False)
        logger.verbose("test verbose")
        assert "test verbose" in stream.getvalue()

    def test_debug(self) -> None:
        """Test debug behavior."""
        stream = StringIO()
        logger = PysymexLogger(level=LogLevel.DEBUG, stream=stream, color=False)
        logger.debug("test debug")
        assert "test debug" in stream.getvalue()

    def test_trace(self) -> None:
        """Test trace behavior."""
        stream = StringIO()
        logger = PysymexLogger(level=LogLevel.TRACE, stream=stream, color=False)
        logger.trace("test trace")
        assert "test trace" in stream.getvalue()

    def test_success(self) -> None:
        """Test success behavior."""
        stream = StringIO()
        logger = PysymexLogger(level=LogLevel.NORMAL, stream=stream, color=False)
        logger.success("success msg")
        assert "[OK] success msg" in stream.getvalue()

    def test_warning(self) -> None:
        """Test warning behavior."""
        stream = StringIO()
        logger = PysymexLogger(level=LogLevel.NORMAL, stream=stream, color=False)
        logger.warning("warning msg")
        assert "[WARN] warning msg" in stream.getvalue()

    def test_error(self) -> None:
        """Test error behavior."""
        stream = StringIO()
        logger = PysymexLogger(level=LogLevel.QUIET, stream=stream, color=False)
        logger.error("error msg")
        assert "[ERR] error msg" in stream.getvalue()

    def test_header(self) -> None:
        """Test header behavior."""
        stream = StringIO()
        logger = PysymexLogger(level=LogLevel.NORMAL, stream=stream, color=False)
        logger.header("head")
        assert "head" in stream.getvalue()
        assert "----" in stream.getvalue()

    def test_rule(self) -> None:
        """Test rule behavior."""
        stream = StringIO()
        logger = PysymexLogger(level=LogLevel.NORMAL, stream=stream, color=False)
        logger.rule("-")
        assert "-" * 60 in stream.getvalue()

    def test_progress(self) -> None:
        """Test progress behavior."""
        stream = StringIO()
        logger = PysymexLogger(level=LogLevel.NORMAL, stream=stream, color=False)
        logger.progress(5, 10, "msg")
        assert "[===============---------------]" in stream.getvalue()
        assert "msg" in stream.getvalue()

    def test_progress_complete(self) -> None:
        """Test progress completion behavior."""
        stream = StringIO()
        logger = PysymexLogger(level=LogLevel.NORMAL, stream=stream, color=False)
        logger.progress(10, 10)
        assert "\n" in stream.getvalue()

    def test_timer(self) -> None:
        """Test timer behavior."""
        stream = StringIO()
        logger = PysymexLogger(level=LogLevel.VERBOSE, stream=stream, color=False)
        with logger.timer("test_time"):
            time.sleep(0.01)
        assert "test_time: " in stream.getvalue()

    def test_count(self) -> None:
        """Test count behavior."""
        logger = PysymexLogger()
        assert logger.count("mycount") == 1
        assert logger.count("mycount", 2) == 3

    def test_get_count(self) -> None:
        """Test get_count behavior."""
        logger = PysymexLogger()
        logger.count("mycount")
        assert logger.get_count("mycount") == 1
        assert logger.get_count("other") == 0

    def test_get_entries_by_level(self) -> None:
        """Test get_entries filtering by level."""
        logger = PysymexLogger(level=LogLevel.NORMAL, history_capacity=10)
        logger.info("info")
        logger.warning("warn")
        logger.error("err")
        entries = logger.get_entries(level=LogLevel.QUIET)
        assert len(entries) == 1
        assert entries[0].message == "err"

    def test_get_entries_by_category(self) -> None:
        """Test get_entries filtering by category."""
        logger = PysymexLogger(level=LogLevel.NORMAL, history_capacity=10)
        logger.info("info")
        logger.warning("warn")
        entries = logger.get_entries(category="warning")
        assert len(entries) == 1
        assert entries[0].message == "warn"

    def test_history_disabled_by_default(self) -> None:
        """Production logging should not retain entries unless history is enabled."""
        logger = PysymexLogger(level=LogLevel.TRACE)
        logger.info("info")
        assert logger.get_entries() == []

    def test_bounded_history_max_length(self) -> None:
        """Explicit history uses a bounded ring buffer."""
        logger = PysymexLogger(level=LogLevel.TRACE, history_capacity=3)
        for i in range(10):
            logger.debug("entry %d", i)
        entries = logger.get_entries()
        assert len(entries) == 3
        assert [entry.message for entry in entries] == ["entry 7", "entry 8", "entry 9"]

    def test_disabled_trace_does_not_evaluate_lazy_message(self) -> None:
        """Disabled trace should return before message resolution."""
        logger = PysymexLogger(level=LogLevel.NORMAL)

        def fail() -> str:
            raise AssertionError("lazy message evaluated")

        logger.trace(fail)

    def test_disabled_debug_does_not_inspect_metadata(self) -> None:
        """Disabled debug should not inspect structured metadata."""
        logger = PysymexLogger(level=LogLevel.NORMAL)
        logger.debug("debug", metadata=ExplodingMetadata())

    def test_disabled_debug_does_not_capture_exception(self) -> None:
        """Disabled debug should not call sys.exc_info for exc_info=True."""
        logger = PysymexLogger(level=LogLevel.NORMAL)
        with patch("pysymex._internal.logging.entry.sys.exc_info") as exc_info:
            logger.debug("debug", exc_info=True)
        exc_info.assert_not_called()

    def test_disabled_debug_does_not_capture_timestamp_or_entry(self) -> None:
        """Disabled debug should not timestamp or construct LogEntry objects."""
        logger = PysymexLogger(level=LogLevel.NORMAL)
        with (
            patch("pysymex._internal.logging.emit.time.time") as timestamp,
            patch("pysymex._internal.logging.emit.LogEntry") as log_entry,
        ):
            logger.debug("debug")
        timestamp.assert_not_called()
        log_entry.assert_not_called()

    def test_level_filtering(self) -> None:
        """Level filtering should keep debug out when the logger is normal."""
        stream = StringIO()
        logger = PysymexLogger(level=LogLevel.NORMAL, stream=stream, color=False)
        logger.debug("debug")
        logger.info("info")
        output = stream.getvalue()
        assert "debug" not in output
        assert "info" in output

    def test_category_filtering(self) -> None:
        """Category filters should be independent of severity."""
        stream = StringIO()
        logger = PysymexLogger(
            level=LogLevel.DEBUG,
            stream=stream,
            color=False,
            categories={LogCategory.SOLVER},
            history_capacity=5,
        )
        logger.debug("solver", category=LogCategory.SOLVER)
        logger.debug("opcode", category=LogCategory.OPCODE)
        assert "solver" in stream.getvalue()
        assert "opcode" not in stream.getvalue()
        assert [entry.message for entry in logger.get_entries()] == ["solver"]

    def test_category_filtering_keeps_status_diagnostics(self) -> None:
        """Category filters must not hide warning/error/success status events."""
        stream = StringIO()
        logger = PysymexLogger(
            level=LogLevel.DEBUG,
            stream=stream,
            color=False,
            categories={LogCategory.SOLVER},
            history_capacity=10,
        )

        logger.warning("warn")
        logger.error("err")
        logger.success("ok")

        output = stream.getvalue()
        assert "[WARN] warn" in output
        assert "[ERR] err" in output
        assert "[OK] ok" in output
        assert [entry.message for entry in logger.get_entries()] == ["warn", "err", "ok"]

    def test_exception_captures_current_exception(self) -> None:
        """logger.exception should capture and lazily format the active exception."""
        stream = StringIO()
        logger = PysymexLogger(level=LogLevel.NORMAL, stream=stream, color=False)
        try:
            raise ValueError("bad value")
        except ValueError:
            logger.exception("failed")
        output = stream.getvalue()
        assert "[ERR] failed" in output
        assert "ValueError: bad value" in output

    def test_open_file(self, tmp_path: Path) -> None:
        """Test open_file behavior."""
        logger = PysymexLogger()
        fp = tmp_path / "log.txt"
        logger.open_file(fp)
        logger.info("file test")
        logger.close()
        assert "file test" in fp.read_text(encoding="utf-8")

    def test_close(self, tmp_path: Path) -> None:
        """Test close behavior."""
        logger = PysymexLogger()
        fp = tmp_path / "log2.txt"
        logger.open_file(fp)
        logger.close()
        assert logger.file_path is None


def test_get_logger() -> None:
    """Test get_logger behavior."""
    logger1 = get_logger()
    logger2 = get_logger()
    assert logger1 is logger2


def test_configure_logging(tmp_path: Path) -> None:
    """Test configure_logging behavior."""
    fp = tmp_path / "conf.log"
    logger = configure_logging(level=LogLevel.DEBUG, color=False, file_path=fp)
    assert logger.level == LogLevel.DEBUG
    assert logger.color is False
    assert logger.file_path == fp
    logger.close()


def test_closed_configured_file_sink_is_removed_from_global_logger(tmp_path: Path) -> None:
    """Closing a configured global file sink must not poison later logging."""
    reset_logging()
    stream = StringIO()
    fp = tmp_path / "closed-global.log"
    logger = configure_logging(
        level=LogLevel.DEBUG,
        color=False,
        file_path=fp,
        stream=stream,
    )

    try:
        logger.close()
        get_logger().debug("after close")

        assert "after close" in stream.getvalue()
    finally:
        reset_logging()


def test_closed_terminal_stream_does_not_poison_later_logging() -> None:
    """Closed capture streams must not turn best-effort diagnostics into failures."""
    stream = StringIO()
    logger = PysymexLogger(level=LogLevel.NORMAL, stream=stream, color=False)
    stream.close()

    logger.warning("after close")
    logger.progress(1, 1, "after close")


def test_configure_logging_with_bounded_history() -> None:
    """Global configuration can explicitly enable bounded history."""
    logger = configure_logging(level=LogLevel.DEBUG, color=False, history_capacity=2)
    logger.debug("one")
    logger.debug("two")
    logger.debug("three")
    assert [entry.message for entry in logger.get_entries()] == ["two", "three"]
    logger.close()
