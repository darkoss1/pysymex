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

"""Bridge from Python stdlib logging to pysymex diagnostics."""

from __future__ import annotations

import logging

from pysymex.logger.categories import LogCategory
from pysymex.logger.global_state import get_logger
from pysymex.logger.levels import LogLevel
from pysymex.logger.logger import PysymexLogger


class PythonLoggingBridge(logging.Handler):
    """Route stdlib logging records into pysymex diagnostics when configured."""

    def __init__(self, target_logger: PysymexLogger | None = None) -> None:
        """Initialize a Python standard logging bridge handler.

        Args:
            target_logger: The PySymex logger instance to receive intercepted
                standard library log records. If not provided, falls back to the
                globally configured PySymex logger.
        """
        super().__init__()
        self.target_logger = target_logger if target_logger is not None else get_logger()
        self._emitting = False

    def emit(self, record: logging.LogRecord) -> None:
        """Emit a stdlib record without recursive bridge dispatch."""
        if self._emitting:
            return
        self._emitting = True
        try:
            level = _map_level(record.levelno)
            child_logger = self.target_logger.with_name(record.name)
            child_logger.log(
                level,
                record.getMessage(),
                category=LogCategory.PYTHON,
                event_name=_event_name(record.levelno),
                exc_info=record.exc_info,
                source_module=record.name,
            )
        except Exception:
            self.handleError(record)
        finally:
            self._emitting = False


def setup_python_logging(level: int = logging.INFO, *, logger_name: str = "pysymex") -> None:
    """Install one stdlib-to-pysymex bridge handler for the named logger."""
    stdlib_logger = logging.getLogger(logger_name)
    stdlib_logger.setLevel(level)
    stdlib_logger.propagate = False
    for handler in stdlib_logger.handlers:
        if isinstance(handler, PythonLoggingBridge):
            handler.setLevel(level)
            handler.target_logger = get_logger(logger_name)
            return
    bridge = PythonLoggingBridge(get_logger(logger_name))
    bridge.setLevel(level)
    stdlib_logger.addHandler(bridge)


def _map_level(level: int) -> LogLevel:
    """Map standard Python logging levels to PySymex LogLevel enums.

    Args:
        level: The integer log level value from the logging record (e.g. logging.INFO).

    Returns:
        The matching LogLevel enum for PySymex diagnostics.
    """
    if level >= logging.ERROR:
        return LogLevel.QUIET
    if level >= logging.DEBUG and level < logging.INFO:
        return LogLevel.DEBUG
    return LogLevel.NORMAL


def _event_name(level: int) -> str | None:
    """Map a standard Python logging level to a diagnostic event name.

    Args:
        level: The integer log level from a standard library log record.

    Returns:
        An event name string (like "error" or "warning"), or None if no
        event designation is required.
    """
    if level >= logging.ERROR:
        return "error"
    if level >= logging.WARNING:
        return "warning"
    return None


__all__ = ["PythonLoggingBridge", "setup_python_logging"]
