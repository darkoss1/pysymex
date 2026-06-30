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

"""Console-only logger helpers."""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import TYPE_CHECKING

from pysymex._internal.logging.emit import LogEventPolicy
from pysymex._internal.logging.levels import LogLevel

if TYPE_CHECKING:
    from collections.abc import Generator

    from pysymex._internal.logging.state import LoggerState


def emit_header(state: LoggerState, message: str) -> None:
    """Emit a CLI header when normal output is enabled."""
    if int(LogLevel.NORMAL) > state.enabled_level or state.terminal is None:
        return
    state.terminal.emit_line(f"\n{message}\n{'-' * len(message)}")


def emit_rule(state: LoggerState, char: str) -> None:
    """Emit a horizontal rule when normal output is enabled."""
    if int(LogLevel.NORMAL) > state.enabled_level or state.terminal is None:
        return
    state.terminal.emit_line(char * 60)


def emit_progress(state: LoggerState, current: int, total: int, message: str) -> None:
    """Render a terminal progress bar when normal output is enabled."""
    if int(LogLevel.NORMAL) > state.enabled_level or state.terminal is None:
        return
    state.terminal.progress(current, total, message)


@contextmanager
def verbose_timer(
    state: LoggerState,
    *,
    logger_name: str,
    name: str,
    category: str,
) -> Generator[None]:
    """Time a block and emit a verbose event when its category is enabled."""
    if not LogEventPolicy.is_enabled(state, category, LogLevel.VERBOSE, None):
        yield
        return
    start = time.perf_counter()
    try:
        yield
    finally:
        elapsed = time.perf_counter() - start
        LogEventPolicy.emit_plain(
            state,
            logger_name=logger_name,
            level=LogLevel.VERBOSE,
            message="%s: %.3fs",
            args=(name, elapsed),
            category=category,
            exc_info=None,
            metadata=None,
        )
