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

"""Core filter pipeline primitives."""

from __future__ import annotations

from collections.abc import Callable, Mapping

FilterFn = Callable[[Mapping[str, object]], bool]
"""A predicate that accepts a parsed event dict and returns True to keep it."""


class FilterPipeline:
    """Composable, ordered chain of :data:`FilterFn` predicates.

    Filters are appended via :meth:`add` and evaluated lazily in insertion
    order by :meth:`matches`.  Because ``all()`` short-circuits on the first
    falsy result, cheap structural checks (e.g. ``event_type`` equality)
    should be added before expensive deep-search predicates.

    Example::

        pipeline = FilterPipeline()
        pipeline.add(lambda e: e.get("event_type") == "step")
        pipeline.add(lambda e: e.get("opcode") == "LOAD_ATTR")
        assert pipeline.matches({"event_type": "step", "opcode": "LOAD_ATTR"})
    """

    __slots__ = ("_filters",)

    def __init__(self) -> None:
        """Initialize an empty filter pipeline.

        Prepares the internal list of filter functions.
        """
        self._filters: list[FilterFn] = []

    def add(self, fn: FilterFn) -> None:
        """Append *fn* to the filter chain."""
        self._filters.append(fn)

    def matches(self, event: Mapping[str, object]) -> bool:
        """Return ``True`` iff all registered filters accept *event*."""
        return all(f(event) for f in self._filters)

    def __len__(self) -> int:
        """Return the number of filter functions registered in the pipeline.

        Returns:
            int: The total count of filters in the pipeline chain.

        """
        return len(self._filters)
