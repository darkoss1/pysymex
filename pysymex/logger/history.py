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

"""Bounded diagnostic history."""

from __future__ import annotations

from collections import deque

from pysymex.logger.entry import LogEntry


class HistoryBuffer:
    """Bounded ring buffer for explicitly enabled diagnostic history."""

    wants_exception = False

    def __init__(self, capacity: int) -> None:
        """Initialize a bounded ring buffer for diagnostic history.

        Args:
            capacity: The maximum number of entries to retain. Must be greater than 0.

        Raises:
            ValueError: If capacity is less than or equal to 0.
        """
        if capacity <= 0:
            raise ValueError("history capacity must be greater than zero")
        self.capacity = capacity
        self._entries: deque[LogEntry] = deque(maxlen=capacity)

    def emit(self, entry: LogEntry) -> None:
        """Store an enabled entry in the bounded ring."""
        self._entries.append(entry)

    def entries(
        self,
        *,
        level: "LogLevel | None" = None,
        category: str | None = None,
    ) -> list[LogEntry]:
        """Return a filtered snapshot of history."""
        entries = list(self._entries)
        if level is not None:
            entries = [entry for entry in entries if entry.level == level]
        if category is not None:
            entries = [entry for entry in entries if entry.category == category]
        return entries

    def clear(self) -> None:
        """Remove all retained entries."""
        self._entries.clear()


from pysymex.logger.levels import LogLevel

__all__ = ["HistoryBuffer"]
