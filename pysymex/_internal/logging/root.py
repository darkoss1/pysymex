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

from typing import TYPE_CHECKING, TextIO

from pysymex._internal.logging.levels import LogLevel
from pysymex._internal.logging.logger import PysymexLogger

if TYPE_CHECKING:
    from pathlib import Path

    from pysymex._internal.logging.categories import CategoryInput
    from pysymex._internal.logging.state import LoggerState

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
    configured_logger = PysymexLogger(
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
    if _root_state is None:
        _root_logger = configured_logger
        _root_state = configured_logger.state
        return configured_logger

    _replace_shared_state(_root_state, configured_logger.state)
    if _root_logger is None:
        _root_logger = PysymexLogger(state=_root_state)
    return _root_logger


def _replace_shared_state(target: LoggerState, source: LoggerState) -> None:
    """Replace logger state in place so existing child loggers follow reconfiguration."""
    target.close()
    target.config = source.config
    target.enabled_level = source.enabled_level
    target.debug_enabled = source.debug_enabled
    target.trace_enabled = source.trace_enabled
    target.sinks = source.sinks
    target.history = source.history
    target.terminal = source.terminal
    target.file_sink = source.file_sink
    target.jsonl_sink = source.jsonl_sink
    target.counters = source.counters


def reset_logging() -> None:
    """Reset global diagnostics state for tests."""
    global _root_logger, _root_state
    if _root_logger is not None:
        _root_logger.close()
    _root_logger = None
    _root_state = None
