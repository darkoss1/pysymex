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

"""Utility helpers for shared typing support."""

from __future__ import annotations

from pysymex.guards import is_set_of_objects


def to_string_set(value: object) -> set[str]:
    """Normalize a dynamic set-like value to a set of strings."""
    result: set[str] = set()
    if is_set_of_objects(value):
        raw_values: set[object] = value
        for item in raw_values:
            if isinstance(item, str):
                result.add(item)
    return result
