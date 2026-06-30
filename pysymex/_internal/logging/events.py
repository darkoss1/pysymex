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

"""Event emission methods mixed into the main diagnostics logger."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.logging.categories import CategoryInput, LogCategory, normalize_category
from pysymex._internal.logging.emit import LogEventPolicy
from pysymex._internal.logging.levels import LogLevel

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pysymex._internal.logging.entry import ExceptionInput, MessageInput
    from pysymex._internal.logging.state import LoggerState


class LoggerEventsMixin:
    """Enabled-event, plain-event, and status methods for ``PysymexLogger``."""

    _state: LoggerState
    name: str

    def is_enabled_for(self, level: LogLevel) -> bool:
        """Return whether a level is enabled without allocating log entries."""
        return int(level) <= self._state.enabled_level

    def is_enabled(self, category: CategoryInput, level: LogLevel) -> bool:
        """Return whether a category/level pair is enabled."""
        return LogEventPolicy.is_enabled(self._state, normalize_category(category), level, None)

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
        if not LogEventPolicy.is_enabled(self._state, category_name, level, event_name):
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
        LogEventPolicy.emit(
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
        LogEventPolicy.emit_plain(
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
        LogEventPolicy.emit_plain(
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
        LogEventPolicy.emit_plain(
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
        LogEventPolicy.emit_plain(
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
