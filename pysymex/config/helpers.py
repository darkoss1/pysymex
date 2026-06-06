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

"""Guard and normalization helpers for pysymex configuration."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TypeGuard

from pysymex.guards import is_dict_of_objects
from pysymex.guards import is_list_of_objects


def is_object_list(value: object) -> TypeGuard[list[object]]:
    """Return True when *value* is a list of runtime objects."""
    return is_list_of_objects(value)


def is_object_collection(
    value: object,
) -> TypeGuard[list[object] | set[object] | tuple[object, ...]]:
    """Return True when *value* is a list/set/tuple of runtime objects."""
    return isinstance(value, (list, set, tuple))


def is_object_dict(value: object) -> TypeGuard[dict[object, object]]:
    """Return True when *value* is a dictionary."""
    return is_dict_of_objects(value)


def is_object_mapping(value: object) -> TypeGuard[Mapping[object, object]]:
    """Return True when *value* is a mapping with runtime object pairs."""
    return isinstance(value, Mapping)


def normalize_object_dict(value: object) -> dict[str, object] | None:
    """Normalize dictionaries to a ``dict[str, object]`` shape."""
    if not is_object_dict(value):
        return None
    normalized: dict[str, object] = {}
    for key_obj, value_obj in value.items():
        normalized[str(key_obj)] = value_obj
    return normalized


def normalize_string_list(value: object) -> list[str] | None:
    """Normalize an object to a list of strings when it is list-like."""
    if not is_object_list(value):
        return None
    normalized: list[str] = []
    for item in value:
        normalized.append(str(item))
    return normalized
