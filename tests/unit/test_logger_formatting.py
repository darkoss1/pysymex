import os
from io import StringIO
from unittest.mock import patch

from pysymex.logger import Colors, LogEntry, LogLevel, supports_color


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

    class DummyStream(StringIO):
        pass

    assert supports_color(DummyStream()) is False


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
