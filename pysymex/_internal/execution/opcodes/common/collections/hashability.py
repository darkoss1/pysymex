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

"""Hashability diagnostics shared by collection construction and mutation opcodes."""

from __future__ import annotations

from collections.abc import Hashable
from typing import cast

from pysymex._internal.core.classes.instances import SymbolicInstance
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.containers.sets import SymbolicSet
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue


def concrete_unhashable_type_error(value: object) -> str | None:
    """Return a definite CPython unhashable-value TypeError message."""
    payload = value.value if isinstance(value, SymbolicValue) and value.value is not None else value
    tuple_items = _retained_tuple_items(payload)
    if tuple_items is not None:
        for item in tuple_items:
            message = concrete_unhashable_type_error(item)
            if message is not None:
                return message
        return None
    if isinstance(payload, (SymbolicList, list)):
        return "unhashable type: 'list'"
    if isinstance(payload, (SymbolicDict, dict)):
        return "unhashable type: 'dict'"
    if isinstance(payload, (SymbolicSet, set)):
        return "unhashable type: 'set'"
    if isinstance(value, (SymbolicValue, SymbolicNoneType, SymbolicString, SymbolicObject)):
        return None
    if isinstance(payload, Hashable):
        return None
    return f"unhashable type: '{type(payload).__name__}'"


def requires_symbolic_object_hashing(value: object) -> bool:
    """Return whether hashing would require unsupported symbolic object semantics."""
    payload = value.value if isinstance(value, SymbolicValue) and value.value is not None else value
    tuple_items = _retained_tuple_items(payload)
    if tuple_items is not None:
        return any(requires_symbolic_object_hashing(item) for item in tuple_items)
    if isinstance(value, SymbolicObject):
        return True
    if isinstance(value, SymbolicInstance):
        return True
    if isinstance(value, SymbolicValue):
        modeled = getattr(value, "_modeled_object", None)
        return isinstance(modeled, SymbolicInstance) and value.value is None
    return False


def _retained_tuple_items(value: object) -> tuple[object, ...] | None:
    """Return exact tuple items retained in Python or tuple-shaped symbolic carriers."""
    if isinstance(value, tuple):
        return cast("tuple[object, ...]", value)
    if isinstance(value, SymbolicList) and getattr(value, "_type", None) == "tuple":
        concrete_items = value.concrete_items
        if concrete_items is None:
            return ()
        return tuple(concrete_items)
    return None
