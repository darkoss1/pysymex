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

"""Convenience operations mixed into the main diagnostics logger."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.logging.console import emit_header, emit_progress, emit_rule, verbose_timer

if TYPE_CHECKING:
    from contextlib import AbstractContextManager
    from pathlib import Path

    from pysymex._internal.logging.entry import LogEntry
    from pysymex._internal.logging.levels import LogLevel
    from pysymex._internal.logging.state import LoggerState


class LoggerOperationsMixin:
    """Non-core convenience methods for ``PysymexLogger``."""

    _state: LoggerState
    name: str

    def header(self, message: str) -> None:
        """Emit a CLI header through the terminal pipeline."""
        emit_header(self._state, message)

    def rule(self, char: str = "-") -> None:
        """Emit a horizontal rule through the terminal pipeline."""
        emit_rule(self._state, char)

    def progress(self, current: int, total: int, message: str = "") -> None:
        """Render a terminal progress bar through the shared emitter."""
        emit_progress(self._state, current, total, message)

    def timer(self, name: str, category: str = "timing") -> AbstractContextManager[None]:
        """Context manager for timing operations."""
        return verbose_timer(self._state, logger_name=self.name, name=name, category=category)

    def count(self, name: str, increment: int = 1) -> int:
        """Increment a named counter and return its value."""
        counters = self._state.counters
        counters[name] = counters.get(name, 0) + increment
        return counters[name]

    def get_count(self, name: str) -> int:
        """Return a named counter value."""
        return self._state.counters.get(name, 0)

    def get_entries(
        self,
        level: LogLevel | None = None,
        category: str | None = None,
    ) -> list[LogEntry]:
        """Return bounded history entries when history is explicitly enabled."""
        if self._state.history is None:
            return []
        return self._state.history.entries(level=level, category=category)

    def open_file(self, path: Path) -> None:
        """Open or replace the text file diagnostics sink."""
        self._state.open_file(path)

    def close(self) -> None:
        """Close owned sink resources."""
        self._state.close()
