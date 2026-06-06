# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Diagnostic sink protocols and implementations."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, TextIO

from pysymex.logger.entry import LogEntry
from pysymex.logger.formatting import format_json_entry, format_log_entry
from pysymex.logger.terminal import TerminalEmitter


class LogSink(Protocol):
    """Sink interface for enabled diagnostic events."""

    wants_exception: bool

    def emit(self, entry: LogEntry) -> None:
        """Consume one enabled entry."""


class TerminalSink:
    """Terminal sink using the unified progress-safe emitter."""

    wants_exception = True

    def __init__(self, emitter: TerminalEmitter, *, color: bool, show_time: bool) -> None:
        """Initialize a terminal diagnostic sink.

        Args:
            emitter: The output writer pipeline.
            color: Whether to use ANSI escape codes.
            show_time: Whether to include timestamps in log headers.
        """
        self._emitter = emitter
        self._color = color
        self._show_time = show_time

    def emit(self, entry: LogEntry) -> None:
        """Write a formatted diagnostic line."""
        line = format_log_entry(entry, color=self._color, show_time=self._show_time)
        if entry.exception is not None:
            line = f"{line}\n{entry.exception.format().rstrip()}"
        self._emitter.emit_line(line)


class FileSink:
    """Text file sink for diagnostics."""

    wants_exception = True

    def __init__(self, path: Path) -> None:
        """Initialize a plain-text file diagnostic sink.

        Creates or overwrites the target file using UTF-8 encoding.

        Args:
            path: The filesystem path to the log file.
        """
        self.path = path
        self._handle: TextIO = path.open("w", encoding="utf-8")

    def emit(self, entry: LogEntry) -> None:
        """Write a plain-text diagnostic entry to disk."""
        line = format_log_entry(entry, color=False, show_time=True)
        if entry.exception is not None:
            line = f"{line}\n{entry.exception.format().rstrip()}"
        self._handle.write(line + "\n")
        self._handle.flush()

    def close(self) -> None:
        """Close the file handle."""
        self._handle.close()


class JsonlSink:
    """JSONL event sink for structured diagnostics."""

    wants_exception = True

    def __init__(self, path: Path) -> None:
        """Initialize a structured JSON lines (JSONL) file sink.

        Creates or overwrites the target file using UTF-8 encoding.

        Args:
            path: The filesystem path to the log file.
        """
        self.path = path
        self._handle: TextIO = path.open("w", encoding="utf-8")

    def emit(self, entry: LogEntry) -> None:
        """Write a compact JSON event to disk."""
        self._handle.write(format_json_entry(entry, include_exception=True) + "\n")
        self._handle.flush()

    def close(self) -> None:
        """Close the file handle."""
        self._handle.close()


__all__ = ["FileSink", "JsonlSink", "LogSink", "TerminalSink"]
