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

"""Helper predicate and type conversion functions for trace analysis."""

from __future__ import annotations

from collections.abc import Mapping

from pysymex.config import is_object_dict, is_object_list


def str_contains(text: str | None, substring: str) -> bool:
    """Return True if *text* is a non-None string containing *substring*."""
    return text is not None and substring in text


def list_contains(lst: list[object] | None, substring: str) -> bool:
    """Return True if any element in *lst* (as string) contains *substring*."""
    if not lst:
        return False
    return any(substring in str(item) for item in lst)


def constraints_contain(constraints: list[object] | None, substring: str) -> bool:
    """Return True if any constraint's ``smtlib`` field contains *substring*."""
    if not constraints:
        return False
    for constraint in constraints:
        constraint_dict = as_dict(constraint)
        if constraint_dict is None:
            continue
        if substring in (as_str(constraint_dict.get("smtlib")) or ""):
            return True
    return False


def as_dict(value: object) -> dict[str, object] | None:
    """Convert value to dict if it represents a dict object."""
    if not is_object_dict(value):
        return None
    normalized: dict[str, object] = {}
    for key_obj, value_obj in value.items():
        normalized[str(key_obj)] = value_obj
    return normalized


def as_list(value: object) -> list[object] | None:
    """Convert value to list if it represents a list object."""
    if not is_object_list(value):
        return None
    return value


def as_str(value: object) -> str | None:
    """Cast value to string if it is a string."""
    return value if isinstance(value, str) else None


def as_int(value: object) -> int | None:
    """Cast value to int if it is an int."""
    return value if isinstance(value, int) else None


def as_float(value: object) -> float | None:
    """Cast value to float if it is an int or float."""
    return float(value) if isinstance(value, (int, float)) else None


def int_field_at_least(event: Mapping[str, object], field: str, minimum: int) -> bool:
    """Return True when integer event field is present and >= *minimum*."""
    value = as_int(event.get(field))
    return value is not None and value >= minimum


def int_field_at_most(event: Mapping[str, object], field: str, maximum: int) -> bool:
    """Return True when integer event field is present and <= *maximum*."""
    value = as_int(event.get(field))
    return value is not None and value <= maximum


def int_field_in_range(
    event: Mapping[str, object],
    field: str,
    lower: int,
    upper: int,
) -> bool:
    """Return True when integer event field is present and within [lower, upper]."""
    value = as_int(event.get(field))
    return value is not None and lower <= value <= upper


def float_field_at_least(event: Mapping[str, object], field: str, minimum: float) -> bool:
    """Return True when numeric event field is present and >= *minimum*."""
    value = as_float(event.get(field))
    return value is not None and value >= minimum


def float_field_at_most(event: Mapping[str, object], field: str, maximum: float) -> bool:
    """Return True when numeric event field is present and <= *maximum*."""
    value = as_float(event.get(field))
    return value is not None and value <= maximum


def float_field_in_range(
    event: Mapping[str, object],
    field: str,
    lower: float,
    upper: float,
) -> bool:
    """Return True when numeric event field is present and within [lower, upper]."""
    value = as_float(event.get(field))
    return value is not None and lower <= value <= upper


def has_stack_pop(event: Mapping[str, object]) -> bool:
    """Return True if event stack diff indicates stack pops."""
    stack_diff = as_dict(event.get("stack_diff"))
    if stack_diff is None:
        return False
    popped = as_int(stack_diff.get("popped"))
    return popped is not None and popped > 0
