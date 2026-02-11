"""Logging framework for PySpectre.
Provides structured logging with configurable verbosity and output formats.
"""

from __future__ import annotations
import logging
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, TextIO


class LogLevel(IntEnum):
    """Log levels for PySpectre."""

    QUIET = 0
    NORMAL = 1
    VERBOSE = 2
    DEBUG = 3
    TRACE = 4


class Colors:
    """ANSI color codes for terminal output."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GRAY = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"


def supports_color(stream: TextIO) -> bool:
    """Check if the stream supports ANSI colors."""
    if not hasattr(stream, "isatty"):
        return False
    if not stream.isatty():
        return False
    if sys.platform == "win32":
        try:
            import os

            return os.environ.get("TERM") or "ANSICON" in os.environ
        except Exception:
            return True
    return True


@dataclass
class LogEntry:
    """A log entry with metadata."""

    level: LogLevel
    message: str
    category: str = "general"
    timestamp: float = field(default_factory=time.time)
    context: dict[str, Any] = field(default_factory=dict)

    def format(self, color: bool = True, show_time: bool = True) -> str:
        """Format the log entry for display."""
        parts = []
        if show_time:
            elapsed = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
            if color:
                parts.append(f"{Colors.GRAY}{elapsed}{Colors.RESET}")
            else:
                parts.append(elapsed)
        level_str = self._level_str(color)
        if level_str:
            parts.append(level_str)
        if self.category != "general":
            if color:
                parts.append(f"{Colors.CYAN}[{self.category}]{Colors.RESET}")
            else:
                parts.append(f"[{self.category}]")
        parts.append(self.message)
        return " ".join(parts)

    def _level_str(self, color: bool) -> str:
        """Get level indicator string."""
        if self.level == LogLevel.QUIET:
            return ""
        indicators = {
            LogLevel.NORMAL: ("•", Colors.WHITE),
            LogLevel.VERBOSE: ("→", Colors.BLUE),
            LogLevel.DEBUG: ("⚙", Colors.MAGENTA),
            LogLevel.TRACE: ("⋯", Colors.GRAY),
        }
        char, col = indicators.get(self.level, ("", ""))
        if color:
            return f"{col}{char}{Colors.RESET}"
        return char


class PySpectreLogger:
    """Main logger for PySpectre."""

    def __init__(
        self,
        level: LogLevel = LogLevel.NORMAL,
        color: bool = True,
        stream: TextIO | None = None,
        file_path: Path | None = None,
    ):
        self.level = level
        self._stream = stream or sys.stdout
        self._color = color and supports_color(self._stream)
        self._file_path = file_path
        self._file_handle: TextIO | None = None
        if file_path is not None:
            self.open_file(file_path)
        self._entries: list[LogEntry] = []
        self._timers: dict[str, float] = {}
        self._counters: dict[str, int] = {}
        self._progress_active = False

    def set_level(self, level: LogLevel) -> None:
        """Set the logging level."""
        self.level = level

    def _should_log(self, level: LogLevel) -> bool:
        """Check if a message at this level should be logged."""
        return level <= self.level

    def _emit(self, entry: LogEntry) -> None:
        """Emit a log entry."""
        self._entries.append(entry)
        if self._should_log(entry.level):
            formatted = entry.format(color=self._color)
            if self._progress_active:
                self._stream.write("\r\033[K")
            self._stream.write(formatted + "\n")
            self._stream.flush()
            if self._file_handle:
                self._file_handle.write(entry.format(color=False) + "\n")
                self._file_handle.flush()

    def log(
        self,
        level: LogLevel,
        message: str,
        category: str = "general",
        **context: Any,
    ) -> None:
        """Log a message at the specified level."""
        entry = LogEntry(
            level=level,
            message=message,
            category=category,
            context=context,
        )
        self._emit(entry)

    def info(self, message: str, **context: Any) -> None:
        """Log an info message."""
        self.log(LogLevel.NORMAL, message, **context)

    def verbose(self, message: str, **context: Any) -> None:
        """Log a verbose message."""
        self.log(LogLevel.VERBOSE, message, **context)

    def debug(self, message: str, **context: Any) -> None:
        """Log a debug message."""
        self.log(LogLevel.DEBUG, message, **context)

    def trace(self, message: str, **context: Any) -> None:
        """Log a trace message."""
        self.log(LogLevel.TRACE, message, **context)

    def success(self, message: str) -> None:
        """Log a success message with green checkmark."""
        if self._should_log(LogLevel.NORMAL):
            if self._color:
                self._stream.write(f"{Colors.GREEN}✓{Colors.RESET} {message}\n")
            else:
                self._stream.write(f"✓ {message}\n")
            self._stream.flush()

    def warning(self, message: str) -> None:
        """Log a warning message."""
        entry = LogEntry(level=LogLevel.NORMAL, message=message, category="warning")
        self._entries.append(entry)
        if self._color:
            self._stream.write(f"{Colors.YELLOW}⚠{Colors.RESET} {message}\n")
        else:
            self._stream.write(f"⚠ {message}\n")
        self._stream.flush()
        if self._file_handle:
            self._file_handle.write(f"⚠ {message}\n")
            self._file_handle.flush()

    def error(self, message: str) -> None:
        """Log an error message (always shown)."""
        entry = LogEntry(level=LogLevel.QUIET, message=message, category="error")
        self._entries.append(entry)
        if self._color:
            self._stream.write(f"{Colors.RED}✗{Colors.RESET} {message}\n")
        else:
            self._stream.write(f"✗ {message}\n")
        self._stream.flush()
        if self._file_handle:
            self._file_handle.write(f"✗ {message}\n")
            self._file_handle.flush()

    def header(self, message: str) -> None:
        """Log a header message."""
        if self._should_log(LogLevel.NORMAL):
            if self._color:
                self._stream.write(f"\n{Colors.BOLD}{Colors.CYAN}{message}{Colors.RESET}\n")
                self._stream.write(f"{Colors.CYAN}{'─' * len(message)}{Colors.RESET}\n")
            else:
                self._stream.write(f"\n{message}\n")
                self._stream.write(f"{'─' * len(message)}\n")
            self._stream.flush()

    def rule(self, char: str = "─") -> None:
        """Print a horizontal rule."""
        if self._should_log(LogLevel.NORMAL):
            width = 60
            if self._color:
                self._stream.write(f"{Colors.GRAY}{char * width}{Colors.RESET}\n")
            else:
                self._stream.write(f"{char * width}\n")
            self._stream.flush()

    def progress(self, current: int, total: int, message: str = "") -> None:
        """Show a progress indicator."""
        if not self._should_log(LogLevel.NORMAL):
            return
        self._progress_active = True
        pct = (current / total * 100) if total > 0 else 0
        bar_width = 30
        filled = int(bar_width * current / total) if total > 0 else 0
        bar = "█" * filled + "░" * (bar_width - filled)
        if self._color:
            status = f"\r{Colors.CYAN}[{bar}]{Colors.RESET} {pct:5.1f}%"
        else:
            status = f"\r[{bar}] {pct:5.1f}%"
        if message:
            status += f" {message}"
        self._stream.write(status)
        self._stream.flush()
        if current >= total:
            self._stream.write("\n")
            self._progress_active = False

    @contextmanager
    def timer(self, name: str, category: str = "timing"):
        """Context manager for timing operations."""
        start = time.perf_counter()
        self._timers[name] = start
        try:
            yield
        finally:
            elapsed = time.perf_counter() - start
            self.verbose(f"{name}: {elapsed:.3f}s", category=category)
            del self._timers[name]

    def count(self, name: str, increment: int = 1) -> int:
        """Increment a counter and return new value."""
        self._counters[name] = self._counters.get(name, 0) + increment
        return self._counters[name]

    def get_count(self, name: str) -> int:
        """Get current counter value."""
        return self._counters.get(name, 0)

    def get_entries(
        self,
        level: LogLevel | None = None,
        category: str | None = None,
    ) -> list[LogEntry]:
        """Get logged entries, optionally filtered."""
        entries = self._entries
        if level is not None:
            entries = [e for e in entries if e.level == level]
        if category is not None:
            entries = [e for e in entries if e.category == category]
        return entries

    def open_file(self, path: Path) -> None:
        """Open a file for logging."""
        self._file_path = path
        self._file_handle = open(path, "w", encoding="utf-8")

    def close(self) -> None:
        """Close any open file handles."""
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None


_logger: PySpectreLogger | None = None


def get_logger() -> PySpectreLogger:
    """Get the global logger instance."""
    global _logger
    if _logger is None:
        _logger = PySpectreLogger()
    return _logger


def set_logger(logger: PySpectreLogger) -> None:
    """Set the global logger instance."""
    global _logger
    _logger = logger


def configure_logging(
    level: LogLevel = LogLevel.NORMAL,
    color: bool = True,
    file_path: Path | None = None,
) -> PySpectreLogger:
    """Configure and return the global logger."""
    global _logger
    _logger = PySpectreLogger(level=level, color=color, file_path=file_path)
    return _logger


class PythonLoggingBridge(logging.Handler):
    """Bridge PySpectre logger to Python's logging module."""

    def __init__(self, shadow_logger: PySpectreLogger):
        super().__init__()
        self.shadow_logger = shadow_logger
        self._level_map = {
            logging.DEBUG: LogLevel.DEBUG,
            logging.INFO: LogLevel.NORMAL,
            logging.WARNING: LogLevel.NORMAL,
            logging.ERROR: LogLevel.QUIET,
            logging.CRITICAL: LogLevel.QUIET,
        }

    def emit(self, record: logging.LogRecord) -> None:
        level = self._level_map.get(record.levelno, LogLevel.NORMAL)
        message = self.format(record)
        if record.levelno >= logging.ERROR:
            self.shadow_logger.error(message)
        elif record.levelno >= logging.WARNING:
            self.shadow_logger.warning(message)
        else:
            self.shadow_logger.log(level, message, category="python")


def setup_python_logging(level: int = logging.INFO) -> None:
    """Setup Python's logging to use PySpectre logger."""
    logger = logging.getLogger("pyspectre")
    logger.setLevel(level)
    logger.addHandler(PythonLoggingBridge(get_logger()))


__all__ = [
    "LogLevel",
    "LogEntry",
    "Colors",
    "PySpectreLogger",
    "get_logger",
    "set_logger",
    "configure_logging",
    "setup_python_logging",
    "supports_color",
]
