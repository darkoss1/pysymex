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

"""Structured diagnostic event models."""

from __future__ import annotations

import sys
import traceback as traceback_module
from dataclasses import dataclass, field
from types import TracebackType
from typing import Callable, Mapping

from pysymex.logger.levels import LogLevel


MessageFactory = Callable[[], str]
MessageInput = str | MessageFactory
ExceptionTuple = tuple[type[BaseException] | None, BaseException | None, TracebackType | None]
ExceptionInput = bool | BaseException | ExceptionTuple | None


@dataclass(frozen=True, slots=True)
class ExceptionInfo:
    """Raw exception data; traceback text is produced only when a sink formats it."""

    exc_type: type[BaseException]
    exc_value: BaseException
    traceback: TracebackType | None

    def format(self) -> str:
        """Format the exception lazily for sinks that need traceback text."""
        return "".join(
            traceback_module.format_exception(self.exc_type, self.exc_value, self.traceback)
        )


@dataclass(frozen=True, slots=True)
class LogEntry:
    """Enabled diagnostic event with structured metadata."""

    level: LogLevel
    message: str
    category: str = "general"
    timestamp: float = 0.0
    logger_name: str = "pysymex"
    source_module: str | None = None
    event_name: str | None = None
    metadata: Mapping[str, object] = field(default_factory=dict[str, object])
    exception: ExceptionInfo | None = None

    def format(self, color: bool = True, show_time: bool = True) -> str:
        """Format the log entry for display."""
        from pysymex.logger.formatting import format_log_entry

        return format_log_entry(self, color=color, show_time=show_time)


def normalize_exception(exc_info: ExceptionInput) -> ExceptionInfo | None:
    """Convert supported exception inputs to raw exception metadata."""
    if exc_info is None:
        return None
    if isinstance(exc_info, bool):
        if not exc_info:
            return None
        exc_type, exc_value, exc_traceback = sys.exc_info()
        if exc_type is None or exc_value is None:
            return None
        return ExceptionInfo(exc_type=exc_type, exc_value=exc_value, traceback=exc_traceback)
    if isinstance(exc_info, BaseException):
        return ExceptionInfo(
            exc_type=type(exc_info),
            exc_value=exc_info,
            traceback=exc_info.__traceback__,
        )
    exc_type, exc_value, exc_traceback = exc_info
    if exc_type is None or exc_value is None:
        return None
    return ExceptionInfo(exc_type=exc_type, exc_value=exc_value, traceback=exc_traceback)


__all__ = [
    "ExceptionInfo",
    "ExceptionInput",
    "ExceptionTuple",
    "LogEntry",
    "MessageFactory",
    "MessageInput",
    "normalize_exception",
]
