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

"""Primitive-value helpers for frontier spill value records."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from .types import JsonPrimitive


class UnsupportedValueSentinel:
    """Sentinel for values that must not cross the spill boundary."""


UNSUPPORTED_VALUE: Final = UnsupportedValueSentinel()


def json_primitive(value: object) -> JsonPrimitive | UnsupportedValueSentinel:
    """Return a JSON primitive for a safe immutable VM root."""
    if type(value) is bool:
        return value
    if type(value) is int:
        return value
    if type(value) is float:
        return value
    if type(value) is str:
        return value
    if value is None:
        return None
    return UNSUPPORTED_VALUE


def is_json_primitive(raw_value: object) -> bool:
    """Return whether ``raw_value`` is a JSON primitive accepted as a VM root."""
    return isinstance(raw_value, (bool, int, float, str)) or raw_value is None
