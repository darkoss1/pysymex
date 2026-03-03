"""Tests for logging framework."""

import pytest

import io

import sys


from pysymex.logging import (
    LogLevel,
    LogEntry,
    Colors,
    PysymexLogger,
    get_logger,
    set_logger,
    configure_logging,
    supports_color,
)


class TestLogLevel:
    """Tests for LogLevel enum."""

    def test_log_levels_ordered(self):
        """Test that log levels are properly ordered."""

        assert LogLevel.QUIET < LogLevel.NORMAL

        assert LogLevel.NORMAL < LogLevel.VERBOSE

        assert LogLevel.VERBOSE < LogLevel.DEBUG

        assert LogLevel.DEBUG < LogLevel.TRACE

    def test_log_level_values(self):
        """Test log level values."""

        assert LogLevel.QUIET == 0

        assert LogLevel.NORMAL == 1


class TestColors:
    """Tests for Colors class."""

    def test_color_codes_exist(self):
        """Test that color codes are defined."""

        assert Colors.RESET is not None

        assert Colors.RED is not None

        assert Colors.GREEN is not None

        assert Colors.CYAN is not None

    def test_color_codes_are_strings(self):
        """Test that color codes are escape sequences."""

        assert isinstance(Colors.RESET, str)

        assert "\033[" in Colors.RESET


class TestLogEntry:
    """Tests for LogEntry."""

    def test_create_entry(self):
        """Test creating a log entry."""

        entry = LogEntry(
            level=LogLevel.NORMAL,
            message="Test message",
            category="test",
        )

        assert entry.level == LogLevel.NORMAL

        assert entry.message == "Test message"

        assert entry.category == "test"

        assert entry.timestamp > 0

    def test_format_with_color(self):
        """Test formatting with color."""

        entry = LogEntry(
            level=LogLevel.NORMAL,
            message="Test",
        )

        formatted = entry.format(color=True)

        assert "Test" in formatted

    def test_format_without_color(self):
        """Test formatting without color."""

        entry = LogEntry(
            level=LogLevel.NORMAL,
            message="Test",
        )

        formatted = entry.format(color=False)

        assert "Test" in formatted

        assert "\033[" not in formatted


class TestPysymexLogger:
    """Tests for PysymexLogger."""

    def test_create_logger(self):
        """Test creating a logger."""

        stream = io.StringIO()

        logger = PysymexLogger(stream=stream)

        assert logger.level == LogLevel.NORMAL

    def test_log_message(self):
        """Test logging a message."""

        stream = io.StringIO()

        logger = PysymexLogger(level=LogLevel.NORMAL, stream=stream, color=False)

        logger.info("Test message")

        output = stream.getvalue()

        assert "Test message" in output

    def test_log_verbose_hidden(self):
        """Test that verbose messages are hidden at normal level."""

        stream = io.StringIO()

        logger = PysymexLogger(level=LogLevel.NORMAL, stream=stream)

        logger.verbose("Verbose message")

        output = stream.getvalue()

        assert "Verbose message" not in output

    def test_log_verbose_shown(self):
        """Test that verbose messages show at verbose level."""

        stream = io.StringIO()

        logger = PysymexLogger(level=LogLevel.VERBOSE, stream=stream, color=False)

        logger.verbose("Verbose message")

        output = stream.getvalue()

        assert "Verbose message" in output

    def test_set_level(self):
        """Test changing log level."""

        stream = io.StringIO()

        logger = PysymexLogger(level=LogLevel.QUIET, stream=stream)

        logger.info("Hidden")

        assert "Hidden" not in stream.getvalue()

        logger.set_level(LogLevel.NORMAL)

        logger.info("Shown")

        assert "Shown" in stream.getvalue()

    def test_success_message(self):
        """Test success message."""

        stream = io.StringIO()

        logger = PysymexLogger(stream=stream, color=False)

        logger.success("All good")

        output = stream.getvalue()

        assert "All good" in output

        assert "✓" in output

    def test_error_message(self):
        """Test error message."""

        stream = io.StringIO()

        logger = PysymexLogger(stream=stream, color=False)

        logger.error("Something wrong")

        output = stream.getvalue()

        assert "Something wrong" in output

        assert "✗" in output

    def test_warning_message(self):
        """Test warning message."""

        stream = io.StringIO()

        logger = PysymexLogger(stream=stream, color=False)

        logger.warning("Be careful")

        output = stream.getvalue()

        assert "Be careful" in output

        assert "⚠" in output

    def test_header_message(self):
        """Test header message."""

        stream = io.StringIO()

        logger = PysymexLogger(stream=stream, color=False)

        logger.header("Section Title")

        output = stream.getvalue()

        assert "Section Title" in output

    def test_timer_context(self):
        """Test timer context manager."""

        import time

        stream = io.StringIO()

        logger = PysymexLogger(level=LogLevel.VERBOSE, stream=stream, color=False)

        with logger.timer("test_op"):
            time.sleep(0.01)

        output = stream.getvalue()

        assert "test_op" in output

    def test_counter(self):
        """Test counting."""

        logger = PysymexLogger()

        assert logger.count("paths") == 1

        assert logger.count("paths") == 2

        assert logger.count("paths", 5) == 7

        assert logger.get_count("paths") == 7

    def test_get_entries(self):
        """Test retrieving logged entries."""

        stream = io.StringIO()

        logger = PysymexLogger(stream=stream)

        logger.info("Message 1")

        logger.verbose("Message 2")

        logger.debug("Message 3")

        entries = logger.get_entries()

        assert len(entries) == 3

        normal_entries = logger.get_entries(level=LogLevel.NORMAL)

        assert len(normal_entries) == 1


class TestGlobalLogger:
    """Tests for global logger functions."""

    def test_get_default_logger(self):
        """Test getting default logger."""

        logger = get_logger()

        assert logger is not None

    def test_set_logger(self):
        """Test setting custom logger."""

        custom_logger = PysymexLogger()

        set_logger(custom_logger)

        assert get_logger() is custom_logger

    def test_configure_logging(self):
        """Test configuring logging."""

        logger = configure_logging(
            level=LogLevel.VERBOSE,
            color=False,
        )

        assert logger.level == LogLevel.VERBOSE


class TestSupportsColor:
    """Tests for color support detection."""

    def test_string_io_no_color(self):
        """Test that StringIO doesn't support color."""

        stream = io.StringIO()

        assert not supports_color(stream)

    def test_non_tty_no_color(self):
        """Test that non-TTY streams don't support color."""

        class NoTTY:
            pass

        assert not supports_color(NoTTY())
