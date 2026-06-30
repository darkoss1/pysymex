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

"""Heap-backed materialization for safe shallow concrete objects."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.identity.addressing import next_address
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.base import SymbolicNoneType, SymbolicType
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.calls.default.materialization.attributes import (
    named_attribute_stack_value,
    receiver_method_attrs,
    safe_object_attrs,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def as_named_object_stack_value(
    name: str,
    value: object,
) -> tuple[SymbolicObject, dict[str, StackValue]] | None:
    """Return a heap-backed object handle for safe shallow concrete instances."""
    if _should_keep_concrete_value(value):
        return None
    attrs = safe_object_attrs(value)
    if attrs is None:
        return None

    address = next_address()
    handle = SymbolicObject(name, address, ConstraintValues.int(address), {address})
    modeled_attrs = {
        str(attr_name): named_attribute_stack_value(name, str(attr_name), attr_value)
        for attr_name, attr_value in attrs.items()
        if isinstance(attr_name, str)
    }
    modeled_attrs.update(receiver_method_attrs(value, modeled_attrs))
    return handle, modeled_attrs


def realize_named_default_objects(
    state: VMState,
    defaults: Mapping[str, object],
    converted: dict[str, StackValue],
) -> tuple[VMState, dict[str, StackValue]]:
    """Materialize safe concrete object defaults while preserving repeated aliases."""
    object_defaults: dict[int, StackValue] = {}
    for name, value in defaults.items():
        key = id(value)
        cached = object_defaults.get(key)
        if cached is not None:
            converted[name] = cached
            continue

        materialized = as_named_object_stack_value(name, value)
        if materialized is None:
            continue
        handle, modeled_attrs = materialized
        state = state.store_heap(handle.address, modeled_attrs)
        converted[name] = handle
        object_defaults[key] = handle
    return state, converted


def _should_keep_concrete_value(value: object) -> bool:
    """Return whether *value* should stay in its existing concrete/stack form."""
    return (
        value is None
        or isinstance(
            value,
            (
                SymbolicValue,
                SymbolicNoneType,
                SymbolicString,
                SymbolicList,
                SymbolicDict,
                SymbolicObject,
                SymbolicType,
                int,
                bool,
                str,
                float,
                bytes,
                type,
                dict,
                list,
                set,
                tuple,
            ),
        )
        or callable(value)
    )
