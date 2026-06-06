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

"""Thread-safe registry for storing and retrieving function summaries."""

from __future__ import annotations

import threading

from pysymex.analysis.runtime.summaries.types import FunctionSummary


class SummaryRegistry:
    """
    Registry of function summaries.
    Stores and retrieves summaries by function name/qualname.
    """

    def __init__(self) -> None:
        self.summaries: dict[str, FunctionSummary] = {}
        self._by_module: dict[str, list[str]] = {}
        self.lock = threading.RLock()

    def register(self, summary: FunctionSummary) -> None:
        """Register a function summary."""
        key = summary.qualname or summary.name
        with self.lock:
            previous = self.summaries.get(key)
            if previous is not None and previous.module and previous.module != summary.module:
                previous_entries = self._by_module.get(previous.module)
                if previous_entries is not None:
                    self._by_module[previous.module] = [
                        entry for entry in previous_entries if entry != key
                    ]
                    if not self._by_module[previous.module]:
                        del self._by_module[previous.module]
            self.summaries[key] = summary
            if summary.module:
                module_entries = self._by_module.setdefault(summary.module, [])
                if key not in module_entries:
                    module_entries.append(key)

    def get(self, name: str) -> FunctionSummary | None:
        """Get summary by name."""
        with self.lock:
            return self.summaries.get(name)

    def get_for_module(self, module: str) -> list[FunctionSummary]:
        """Get all summaries for a module."""
        with self.lock:
            names = list(self._by_module.get(module, []))
            return [self.summaries[n] for n in names if n in self.summaries]

    def has(self, name: str) -> bool:
        """Check if summary exists."""
        with self.lock:
            return name in self.summaries

    def all_summaries(self) -> list[FunctionSummary]:
        """Get all registered summaries."""
        with self.lock:
            return list(self.summaries.values())

    def clear(self) -> None:
        """Clear all summaries."""
        with self.lock:
            self.summaries.clear()
            self._by_module.clear()


SUMMARY_REGISTRY = SummaryRegistry()


def get_summary(name: str) -> FunctionSummary | None:
    """Get summary from global registry."""
    return SUMMARY_REGISTRY.get(name)


def register_summary(summary: FunctionSummary) -> None:
    """Register summary in global registry."""
    SUMMARY_REGISTRY.register(summary)
