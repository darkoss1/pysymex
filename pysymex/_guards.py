# pysymex: Python Symbolic Execution & Formal Verification
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

"""Dependency-free runtime shape guards shared across early-import modules."""

from __future__ import annotations

from typing import TypeGuard


def is_list_of_objects(value: object) -> TypeGuard[list[object]]:
    """Return whether *value* is a list of runtime objects."""
    return isinstance(value, list)


def is_tuple_of_objects(value: object) -> TypeGuard[tuple[object, ...]]:
    """Return whether *value* is a tuple of runtime objects."""
    return isinstance(value, tuple)


def is_dict_of_objects(value: object) -> TypeGuard[dict[object, object]]:
    """Return whether *value* is a dictionary of runtime objects."""
    return isinstance(value, dict)


def is_set_of_objects(value: object) -> TypeGuard[set[object]]:
    """Return whether *value* is a set of runtime objects."""
    return isinstance(value, set)
