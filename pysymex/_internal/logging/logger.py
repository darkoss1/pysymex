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

"""Main pysymex diagnostics API."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, TextIO

from pysymex._internal.logging.events import LoggerEventsMixin
from pysymex._internal.logging.levels import LogLevel
from pysymex._internal.logging.operations import LoggerOperationsMixin
from pysymex._internal.logging.state import LoggerState, create_logger_state

if TYPE_CHECKING:
    from pathlib import Path

    from pysymex._internal.logging.categories import CategoryInput


class PysymexLogger(LoggerEventsMixin, LoggerOperationsMixin):
    """Pysymex-specific diagnostics logger optimized for disabled hot paths."""

    def __init__(
        self,
        level: LogLevel = LogLevel.NORMAL,
        color: bool = True,
        stream: TextIO | None = None,
        file_path: Path | None = None,
        *,
        name: str = "pysymex",
        categories: set[CategoryInput] | frozenset[CategoryInput] | None = None,
        history_capacity: int = 0,
        jsonl_path: Path | None = None,
        deterministic: bool = False,
        show_time: bool = True,
        state: LoggerState | None = None,
    ) -> None:
        """Initialize the PySymex diagnostic logger.

        Either constructs a new global or child logging state with target streams,
        files, and filters, or reuses a shared LoggerState instance to unify
        configuration across sub-loggers.

        Args:
            level: Active log level. Defaults to LogLevel.NORMAL.
            color: Whether to use ANSI terminal colors. Defaults to True.
            stream: Target stream for console output. Defaults to sys.stdout.
            file_path: Optional path to write plain text diagnostics to.
            name: The logger identifier. Defaults to "pysymex".
            categories: Categories of logging to enable.
            history_capacity: Capacity of the bounded history buffer. Defaults to 0.
            jsonl_path: Optional path to write structured JSON lines to.
            deterministic: Suppress timestamps for deterministic output. Defaults to False.
            show_time: Whether to output time tags. Defaults to True.
            state: Shared LoggerState. If provided, configuration parameters are ignored.

        """
        self.name = name
        if state is not None:
            self._state = state
            return

        target_stream = stream or sys.stdout
        self._state = create_logger_state(
            level=level,
            color=color,
            stream=target_stream,
            file_path=file_path,
            categories=categories,
            history_capacity=history_capacity,
            jsonl_path=jsonl_path,
            deterministic=deterministic,
            show_time=show_time,
        )

    @property
    def state(self) -> LoggerState:
        """Retrieve the underlying logger state object.

        Returns:
            The LoggerState instance containing the sinks, configuration,
            and cached flags for hot paths.

        """
        return self._state

    @property
    def level(self) -> LogLevel:
        """Retrieve the active log level."""
        return self._state.config.level

    @level.setter
    def level(self, level: LogLevel) -> None:
        """Update the active log level and sync hot path cache flags.

        Args:
            level: The new LogLevel to configure.

        """
        self._state.config.level = level
        self._state.enabled_level = int(level)
        self._state.debug_enabled = int(level) >= 3
        self._state.trace_enabled = int(level) >= 4

    @property
    def color(self) -> bool:
        """Check if ANSI color output is enabled for terminal emission.

        Returns:
            True if colors are enabled, False otherwise.

        """
        return self._state.config.color

    @property
    def file_path(self) -> Path | None:
        """Retrieve the file path of the active plain-text file sink.

        Returns:
            The path of the file sink if active, or None if no file sink
            is configured.

        """
        return self._state.file_sink.path if self._state.file_sink is not None else None

    def with_name(self, name: str) -> PysymexLogger:
        """Create a cheap child logger that shares sinks and configuration."""
        return PysymexLogger(name=name, state=self._state)

    def set_level(self, level: LogLevel) -> None:
        """Set the logging level."""
        self._state.config.level = level
        self._state.enabled_level = int(level)
        self._state.debug_enabled = int(level) >= 3
        self._state.trace_enabled = int(level) >= 4

    def set_categories(
        self,
        categories: set[CategoryInput] | frozenset[CategoryInput] | None,
    ) -> None:
        """Replace enabled category filtering."""
        from pysymex._internal.logging.categories import normalize_categories

        self._state.config.enabled_categories = (
            normalize_categories(categories) if categories is not None else None
        )
