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

"""Global logger configuration."""

from __future__ import annotations

from pathlib import Path
from typing import TextIO

from pysymex.logger.categories import CategoryInput
from pysymex.logger.levels import LogLevel
from pysymex.logger.logger import PysymexLogger
from pysymex.logger.state import LoggerState

_root_logger: PysymexLogger | None = None
_root_state: LoggerState | None = None


def get_logger(name: str = "pysymex") -> PysymexLogger:
    """Get a shared logger, optionally named for source metadata."""
    global _root_logger, _root_state
    if _root_logger is None:
        _root_logger = PysymexLogger()
        _root_state = _root_logger.state
    if name == _root_logger.name:
        return _root_logger
    if _root_state is None:
        _root_state = _root_logger.state
    return PysymexLogger(name=name, state=_root_state)


def set_logger(new_logger: PysymexLogger) -> None:
    """Set the global logger instance."""
    global _root_logger, _root_state
    _root_logger = new_logger
    _root_state = new_logger.state


def configure_logging(
    level: LogLevel = LogLevel.NORMAL,
    color: bool = True,
    file_path: Path | None = None,
    *,
    stream: TextIO | None = None,
    categories: set[CategoryInput] | frozenset[CategoryInput] | None = None,
    history_capacity: int = 0,
    jsonl_path: Path | None = None,
    deterministic: bool = False,
    show_time: bool = True,
) -> PysymexLogger:
    """Configure and return the global logger."""
    global _root_logger, _root_state
    if _root_logger is not None:
        _root_logger.close()
    _root_logger = PysymexLogger(
        level=level,
        color=color,
        stream=stream,
        file_path=file_path,
        categories=categories,
        history_capacity=history_capacity,
        jsonl_path=jsonl_path,
        deterministic=deterministic,
        show_time=show_time,
    )
    _root_state = _root_logger.state
    return _root_logger


def reset_logging() -> None:
    """Reset global diagnostics state for tests."""
    global _root_logger, _root_state
    if _root_logger is not None:
        _root_logger.close()
    _root_logger = None
    _root_state = None


__all__ = ["configure_logging", "get_logger", "reset_logging", "set_logger"]
