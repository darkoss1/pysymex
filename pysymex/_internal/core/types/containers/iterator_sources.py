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

"""Live source descriptors for modeled lazy iterator builtins."""

from __future__ import annotations

from dataclasses import dataclass, replace


@dataclass(frozen=True, slots=True)
class EnumerateIteratorSource:
    """Source retained by ``enumerate`` so later source mutations stay visible."""

    iterable: object
    start: int

    def with_iterable(self, iterable: object) -> EnumerateIteratorSource:
        """Return this source retargeted to an updated iterable."""
        return replace(self, iterable=iterable)


@dataclass(frozen=True, slots=True)
class ZipIteratorSource:
    """Sources retained by non-strict ``zip`` for lazy shortest-length iteration."""

    iterables: tuple[object, ...]

    def with_iterables(self, iterables: tuple[object, ...]) -> ZipIteratorSource:
        """Return this source retargeted to updated iterables."""
        return replace(self, iterables=iterables)


@dataclass(frozen=True, slots=True)
class MapIteratorSource:
    """Source retained by exact single-iterable ``map`` modeling."""

    function: object
    iterable: object

    def with_iterable(self, iterable: object) -> MapIteratorSource:
        """Return this source retargeted to an updated iterable."""
        return replace(self, iterable=iterable)


@dataclass(frozen=True, slots=True)
class FilterIteratorSource:
    """Source retained by exact truth-filter modeling."""

    predicate: object
    iterable: object

    def with_iterable(self, iterable: object) -> FilterIteratorSource:
        """Return this source retargeted to an updated iterable."""
        return replace(self, iterable=iterable)
