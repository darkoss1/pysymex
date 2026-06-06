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

"""Shared bytecode helpers for dead-code detectors."""

from __future__ import annotations

from pysymex.guards import is_tuple_of_objects as _is_object_tuple_guard
from pysymex.core.cache import get_instructions as cached_get_instructions


def as_object_tuple(value: object) -> tuple[object, ...]:
    """Return a value as tuple[object, ...] when it is a tuple."""
    if _is_object_tuple_guard(value):
        return tuple(value)
    return ()


__all__ = ["as_object_tuple", "cached_get_instructions"]
