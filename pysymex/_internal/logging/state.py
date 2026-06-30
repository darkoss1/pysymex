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

"""Shared logger state and sink construction."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TextIO

from pysymex._internal.config.logging.settings import LoggerConfig
from pysymex._internal.logging.formatting import supports_color
from pysymex._internal.logging.history import HistoryBuffer
from pysymex._internal.logging.sinks import FileSink, JsonlSink, LogSink, TerminalSink
from pysymex._internal.logging.terminal import TerminalEmitter

if TYPE_CHECKING:
    from pathlib import Path

    from pysymex._internal.logging.categories import CategoryInput
    from pysymex._internal.logging.levels import LogLevel


@dataclass(slots=True)
class LoggerState:
    """Shared mutable diagnostics state for a root logger and children."""

    config: LoggerConfig
    enabled_level: int
    debug_enabled: bool
    trace_enabled: bool
    sinks: list[LogSink] = field(default_factory=list[LogSink])
    history: HistoryBuffer | None = None
    terminal: TerminalEmitter | None = None
    file_sink: FileSink | None = None
    jsonl_sink: JsonlSink | None = None
    counters: dict[str, int] = field(default_factory=dict[str, int])

    def open_file(self, path: Path) -> None:
        """Open or replace the text file diagnostics sink."""
        if self.file_sink is not None:
            self.sinks.remove(self.file_sink)
            self.file_sink.close()
        self.file_sink = FileSink(path)
        self.sinks.append(self.file_sink)

    def close(self) -> None:
        """Close owned sinks."""
        if self.file_sink is not None:
            if self.file_sink in self.sinks:
                self.sinks.remove(self.file_sink)
            self.file_sink.close()
            self.file_sink = None
        if self.jsonl_sink is not None:
            if self.jsonl_sink in self.sinks:
                self.sinks.remove(self.jsonl_sink)
            self.jsonl_sink.close()
            self.jsonl_sink = None


def create_logger_state(
    *,
    level: LogLevel,
    color: bool,
    stream: TextIO,
    file_path: Path | None,
    categories: set[CategoryInput] | frozenset[CategoryInput] | None,
    history_capacity: int,
    jsonl_path: Path | None,
    deterministic: bool,
    show_time: bool,
) -> LoggerState:
    """Build root logger state and owned sinks."""
    config = LoggerConfig.create(
        level=level,
        color=color and supports_color(stream),
        categories=categories,
        show_time=show_time,
        deterministic=deterministic,
    )
    terminal = TerminalEmitter(stream)
    history = HistoryBuffer(history_capacity) if history_capacity > 0 else None
    terminal_sink = TerminalSink(terminal, color=config.color, show_time=config.show_time)
    sinks: list[LogSink] = [terminal_sink]
    file_sink = FileSink(file_path) if file_path is not None else None
    if file_sink is not None:
        sinks.append(file_sink)
    jsonl_sink = JsonlSink(jsonl_path) if jsonl_path is not None else None
    if jsonl_sink is not None:
        sinks.append(jsonl_sink)
    if history is not None:
        sinks.append(history)
    return LoggerState(
        config=config,
        enabled_level=int(config.level),
        debug_enabled=int(config.level) >= 3,
        trace_enabled=int(config.level) >= 4,
        sinks=sinks,
        history=history,
        terminal=terminal,
        file_sink=file_sink,
        jsonl_sink=jsonl_sink,
    )
