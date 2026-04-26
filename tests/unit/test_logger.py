import os
import time
import logging
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from pysymex.logger import (
    LogLevel,
    Colors,
    supports_color,
    LogEntry,
    PysymexLogger,
    get_logger,
    set_logger,
    configure_logging,
    PythonLoggingBridge,
    setup_python_logging,
)


class TestLogLevel:
    """Test suite for pysymex.logger.LogLevel."""

    def test_values(self) -> None:
        """Test LogLevel values."""
        assert LogLevel.QUIET == 0
        assert LogLevel.NORMAL == 1
        assert LogLevel.VERBOSE == 2
        assert LogLevel.DEBUG == 3
        assert LogLevel.TRACE == 4


class TestColors:
    """Test suite for pysymex.logger.Colors."""

    def test_constants(self) -> None:
        """Test basic initialization of color codes."""
        assert Colors.RESET == "\033[0m"
        assert Colors.RED == "\033[31m"


class TTYStream(StringIO):
    """Mock TextIO stream with isatty returning True."""

    def isatty(self) -> bool:
        """Return True."""
        return True


def test_supports_color_no_isatty() -> None:
    """Test supports_color behavior when stream has no isatty."""

    class DummyStream:
        pass

    assert supports_color(DummyStream()) is False  # type: ignore[arg-type]  # Testing invalid input type


def test_supports_color_isatty_false() -> None:
    """Test supports_color behavior when stream isatty is false."""
    assert supports_color(StringIO()) is False


def test_supports_color_isatty_true_non_win32() -> None:
    """Test supports_color behavior on non-win32."""
    with patch("sys.platform", "linux"):
        assert supports_color(TTYStream()) is True


def test_supports_color_isatty_true_win32() -> None:
    """Test supports_color behavior on win32."""
    with patch("sys.platform", "win32"):
        with patch.dict(os.environ, {"TERM": "xterm"}):
            assert supports_color(TTYStream()) is True


class TestLogEntry:
    """Test suite for pysymex.logger.LogEntry."""

    def test_format_with_color_and_time(self) -> None:
        """Test format behavior with color and time."""
        entry = LogEntry(level=LogLevel.NORMAL, message="test", timestamp=1000.0)
        formatted = entry.format(color=True, show_time=True)
        assert Colors.GRAY in formatted
        assert "test" in formatted

    def test_format_without_color(self) -> None:
        """Test format behavior without color."""
        entry = LogEntry(level=LogLevel.NORMAL, message="test", timestamp=1000.0)
        formatted = entry.format(color=False, show_time=True)
        assert Colors.GRAY not in formatted
        assert "test" in formatted

    def test_format_without_time(self) -> None:
        """Test format behavior without time."""
        entry = LogEntry(level=LogLevel.NORMAL, message="test", timestamp=1000.0)
        formatted = entry.format(color=False, show_time=False)
        assert ":" not in formatted

    def test_format_category(self) -> None:
        """Test format behavior with category."""
        entry = LogEntry(level=LogLevel.NORMAL, message="test", category="sys", timestamp=1000.0)
        formatted = entry.format(color=False, show_time=False)
        assert "[sys]" in formatted


class TestPysymexLogger:
    """Test suite for pysymex.logger.PysymexLogger."""

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
        assert "✓ success msg" in stream.getvalue()

    def test_warning(self) -> None:
        """Test warning behavior."""
        stream = StringIO()
        logger = PysymexLogger(level=LogLevel.NORMAL, stream=stream, color=False)
        logger.warning("warning msg")
        assert "⚠ warning msg" in stream.getvalue()

    def test_error(self) -> None:
        """Test error behavior."""
        stream = StringIO()
        logger = PysymexLogger(level=LogLevel.QUIET, stream=stream, color=False)
        logger.error("error msg")
        assert "✗ error msg" in stream.getvalue()

    def test_header(self) -> None:
        """Test header behavior."""
        stream = StringIO()
        logger = PysymexLogger(level=LogLevel.NORMAL, stream=stream, color=False)
        logger.header("head")
        assert "head" in stream.getvalue()
        assert "────" in stream.getvalue()

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
        assert "[███████████████░░░░░░░░░░░░░░░]" in stream.getvalue()
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
        logger = PysymexLogger(level=LogLevel.NORMAL)
        logger.info("info")
        logger.warning("warn")
        logger.error("err")
        entries = logger.get_entries(level=LogLevel.QUIET)
        assert len(entries) == 1
        assert entries[0].message == "err"

    def test_get_entries_by_category(self) -> None:
        """Test get_entries filtering by category."""
        logger = PysymexLogger(level=LogLevel.NORMAL)
        logger.info("info")
        logger.warning("warn")
        entries = logger.get_entries(category="warning")
        assert len(entries) == 1
        assert entries[0].message == "warn"

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
        assert logger._file_handle is None  # type: ignore[reportPrivateUsage]  # Verifying internal state reset


def test_get_logger() -> None:
    """Test get_logger behavior."""
    logger1 = get_logger()
    logger2 = get_logger()
    assert logger1 is logger2


def test_set_logger() -> None:
    """Test set_logger behavior."""
    old_logger = get_logger()
    new_logger = PysymexLogger()
    set_logger(new_logger)
    assert get_logger() is new_logger
    set_logger(old_logger)


def test_configure_logging(tmp_path: Path) -> None:
    """Test configure_logging behavior."""
    fp = tmp_path / "conf.log"
    logger = configure_logging(level=LogLevel.DEBUG, color=False, file_path=fp)
    assert logger.level == LogLevel.DEBUG
    assert logger._color is False  # type: ignore[reportPrivateUsage]  # Verifying internal state
    assert logger._file_path == fp  # type: ignore[reportPrivateUsage]  # Verifying internal state
    logger.close()


class TestPythonLoggingBridge:
    """Test suite for pysymex.logger.PythonLoggingBridge."""

    def test_emit_error(self) -> None:
        """Test emit behavior for errors."""
        stream = StringIO()
        target = PysymexLogger(stream=stream, color=False)
        bridge = PythonLoggingBridge(target)
        record = logging.LogRecord("test", logging.ERROR, "", 0, "err", (), None)
        bridge.emit(record)
        assert "✗ err" in stream.getvalue()

    def test_emit_warning(self) -> None:
        """Test emit behavior for warnings."""
        stream = StringIO()
        target = PysymexLogger(stream=stream, color=False)
        bridge = PythonLoggingBridge(target)
        record = logging.LogRecord("test", logging.WARNING, "", 0, "warn", (), None)
        bridge.emit(record)
        assert "⚠ warn" in stream.getvalue()

    def test_emit_info(self) -> None:
        """Test emit behavior for info."""
        stream = StringIO()
        target = PysymexLogger(stream=stream, color=False)
        bridge = PythonLoggingBridge(target)
        record = logging.LogRecord("test", logging.INFO, "", 0, "info", (), None)
        bridge.emit(record)
        assert "info" in stream.getvalue()


def test_setup_python_logging() -> None:
    """Test setup_python_logging behavior."""
    setup_python_logging()
    py_logger = logging.getLogger("pysymex")
    assert any(isinstance(h, PythonLoggingBridge) for h in py_logger.handlers)
