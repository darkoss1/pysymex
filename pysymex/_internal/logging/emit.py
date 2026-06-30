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

"""Enabled-event construction for the diagnostics logger."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from pysymex._internal.logging.categories import CategoryInput, normalize_category
from pysymex._internal.logging.entry import (
    ExceptionInput,
    LogEntry,
    LogEntryPolicy,
    MessageInput,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pysymex._internal.logging.levels import LogLevel
    from pysymex._internal.logging.state import LoggerState


class LogEventPolicy:
    """Domain owner for logger enablement checks and event emission."""

    @staticmethod
    def is_enabled(
        state: LoggerState,
        category_name: str,
        level: LogLevel,
        event_name: str | None,
    ) -> bool:
        """Return whether an event is enabled after level and category policy."""
        if int(level) > state.enabled_level:
            return False
        if event_name in {"error", "warning", "success"}:
            return True
        if category_name in {"error", "warning", "success"}:
            return True
        enabled_categories = state.config.enabled_categories
        if enabled_categories is None:
            return True
        return category_name in enabled_categories

    @staticmethod
    def emit(
        state: LoggerState,
        *,
        logger_name: str,
        level: LogLevel,
        message: MessageInput,
        args: tuple[object, ...],
        category_name: str,
        event_name: str | None,
        exc_info: ExceptionInput,
        source_module: str | None,
        metadata: Mapping[str, object] | None,
        metadata_kwargs: Mapping[str, object],
    ) -> None:
        """Build and dispatch an event after enablement is already proven."""
        resolved_message = LogEventPolicy.format_message(message, args)
        resolved_exception = LogEntryPolicy.exception(exc_info)
        if metadata is None:
            event_metadata = metadata_kwargs
        elif metadata_kwargs:
            event_metadata = {**metadata, **metadata_kwargs}
        else:
            event_metadata = metadata

        entry = LogEntry(
            level=level,
            message=resolved_message,
            category=category_name,
            timestamp=0.0 if state.config.deterministic else time.time(),
            logger_name=logger_name,
            source_module=source_module,
            event_name=event_name,
            metadata=event_metadata,
            exception=resolved_exception,
        )
        for sink in state.sinks:
            sink.emit(entry)

    @staticmethod
    def emit_plain(
        state: LoggerState,
        *,
        logger_name: str,
        level: LogLevel,
        message: MessageInput,
        args: tuple[object, ...],
        category: CategoryInput,
        exc_info: ExceptionInput,
        metadata: Mapping[str, object] | None,
    ) -> None:
        """Emit a standard level/category event if enabled."""
        category_name = normalize_category(category)
        if not LogEventPolicy.is_enabled(state, category_name, level, None):
            return
        LogEventPolicy.emit(
            state,
            logger_name=logger_name,
            level=level,
            message=message,
            args=args,
            category_name=category_name,
            event_name=None,
            exc_info=exc_info,
            source_module=None,
            metadata=metadata,
            metadata_kwargs={},
        )

    @staticmethod
    def format_message(message: MessageInput, args: tuple[object, ...]) -> str:
        """Resolve lazy and %-formatted messages."""
        raw_message = message() if callable(message) else message
        if not args:
            return raw_message
        try:
            return raw_message % args
        except Exception:
            rendered_args = ", ".join(str(arg) for arg in args)
            return f"{raw_message} {rendered_args}"
