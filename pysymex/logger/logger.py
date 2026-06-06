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
from pathlib import Path
from typing import Mapping, TextIO

from pysymex.logger.categories import CategoryInput, LogCategory, normalize_category
from pysymex.logger.emit import emit_enabled_event, emit_plain_event, is_enabled_event
from pysymex.logger.entry import ExceptionInput, MessageInput
from pysymex.logger.levels import LogLevel
from pysymex.logger.operations import PysymexLoggerOperationsMixin
from pysymex.logger.state import LoggerState, create_logger_state


class PysymexLogger(PysymexLoggerOperationsMixin):
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
        self, categories: set[CategoryInput] | frozenset[CategoryInput] | None
    ) -> None:
        """Replace enabled category filtering."""
        from pysymex.logger.categories import normalize_categories

        self._state.config.enabled_categories = (
            normalize_categories(categories) if categories is not None else None
        )

    def is_enabled_for(self, level: LogLevel) -> bool:
        """Return whether a level is enabled without allocating log entries."""
        return int(level) <= self._state.enabled_level

    def is_enabled(self, category: CategoryInput, level: LogLevel) -> bool:
        """Return whether a category/level pair is enabled."""
        return is_enabled_event(self._state, normalize_category(category), level, None)

    def log(
        self,
        level: LogLevel,
        message: MessageInput,
        *args: object,
        category: CategoryInput = LogCategory.GENERAL,
        event_name: str | None = None,
        exc_info: ExceptionInput = None,
        source_module: str | None = None,
        metadata: Mapping[str, object] | None = None,
        **metadata_kwargs: object,
    ) -> None:
        """Log an enabled event; disabled calls return before expensive work."""
        category_name = normalize_category(category)
        if not is_enabled_event(self._state, category_name, level, event_name):
            return
        self._log_enabled(
            level,
            message,
            args,
            category_name=category_name,
            event_name=event_name,
            exc_info=exc_info,
            source_module=source_module,
            metadata=metadata,
            metadata_kwargs=metadata_kwargs,
        )

    def _log_enabled(
        self,
        level: LogLevel,
        message: MessageInput,
        args: tuple[object, ...],
        *,
        category_name: str,
        event_name: str | None,
        exc_info: ExceptionInput,
        source_module: str | None,
        metadata: Mapping[str, object] | None,
        metadata_kwargs: Mapping[str, object],
    ) -> None:
        """Build and dispatch an event after enablement is already proven."""
        emit_enabled_event(
            self._state,
            logger_name=self.name,
            level=level,
            message=message,
            args=args,
            category_name=category_name,
            event_name=event_name,
            exc_info=exc_info,
            source_module=source_module,
            metadata=metadata,
            metadata_kwargs=metadata_kwargs,
        )

    def info(
        self,
        message: MessageInput,
        *args: object,
        category: CategoryInput = LogCategory.GENERAL,
        exc_info: ExceptionInput = None,
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        """Log a normal message."""
        emit_plain_event(
            self._state,
            logger_name=self.name,
            level=LogLevel.NORMAL,
            message=message,
            args=args,
            category=category,
            exc_info=exc_info,
            metadata=metadata,
        )

    def verbose(
        self,
        message: MessageInput,
        *args: object,
        category: CategoryInput = LogCategory.GENERAL,
        exc_info: ExceptionInput = None,
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        """Log a verbose message."""
        emit_plain_event(
            self._state,
            logger_name=self.name,
            level=LogLevel.VERBOSE,
            message=message,
            args=args,
            category=category,
            exc_info=exc_info,
            metadata=metadata,
        )

    def debug(
        self,
        message: MessageInput,
        *args: object,
        category: CategoryInput = LogCategory.GENERAL,
        exc_info: ExceptionInput = None,
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        """Log a debug message."""
        if not self._state.debug_enabled:
            return
        emit_plain_event(
            self._state,
            logger_name=self.name,
            level=LogLevel.DEBUG,
            message=message,
            args=args,
            category=category,
            exc_info=exc_info,
            metadata=metadata,
        )

    def trace(
        self,
        message: MessageInput,
        *args: object,
        category: CategoryInput = LogCategory.GENERAL,
        exc_info: ExceptionInput = None,
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        """Log a trace message."""
        if not self._state.trace_enabled:
            return
        emit_plain_event(
            self._state,
            logger_name=self.name,
            level=LogLevel.TRACE,
            message=message,
            args=args,
            category=category,
            exc_info=exc_info,
            metadata=metadata,
        )

    def exception(
        self,
        message: MessageInput,
        *args: object,
        category: CategoryInput = LogCategory.GENERAL,
        exc_info: ExceptionInput = True,
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        """Log the current exception as an error."""
        self.log(
            LogLevel.QUIET,
            message,
            *args,
            category=category,
            event_name="error",
            exc_info=exc_info,
            metadata=metadata,
        )

    def success(
        self,
        message: MessageInput,
        *args: object,
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        """Log a success status."""
        self.log(
            LogLevel.NORMAL,
            message,
            *args,
            category=LogCategory.SUCCESS,
            event_name="success",
            metadata=metadata,
        )

    def warning(
        self,
        message: MessageInput,
        *args: object,
        exc_info: ExceptionInput = None,
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        """Log a warning status."""
        self.log(
            LogLevel.NORMAL,
            message,
            *args,
            category=LogCategory.WARNING,
            event_name="warning",
            exc_info=exc_info,
            metadata=metadata,
        )

    def error(
        self,
        message: MessageInput,
        *args: object,
        exc_info: ExceptionInput = None,
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        """Log an error status."""
        self.log(
            LogLevel.QUIET,
            message,
            *args,
            category=LogCategory.ERROR,
            event_name="error",
            exc_info=exc_info,
            metadata=metadata,
        )


__all__ = ["LoggerState", "PysymexLogger"]
