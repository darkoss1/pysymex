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

"""Symbolic-object heap lookup for ``LOAD_ATTR`` and ``LOAD_METHOD``."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.calls.object.maps import (
    bind_heap_modeled_method,
    is_object_map,
    map_get,
    map_set,
    map_to_stack_dict,
)
from pysymex._internal.execution.calls.value.coercion import coerce_call_stack_value
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.functions.attribute.load.results import (
    modeled_attribute_carrier,
)
from pysymex._internal.models.registry import RuntimeModelRegistry

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.types.containers.objects import SymbolicObject


@dataclass(frozen=True)
class ObjectAttributeLoad:
    """Result of heap-backed symbolic object attribute lookup."""

    state: VMState
    result_val: object | None
    obj_state: object | None
    type_name: str
    immediate_result: OpcodeResult | None = None


def _object_state_type_name(obj_state: object) -> str:
    """Return the modeled runtime type name for a heap object state."""
    if isinstance(obj_state, SymbolicList):
        return getattr(obj_state, "_type", None) or "list"
    if isinstance(obj_state, SymbolicDict):
        return getattr(obj_state, "_type", None) or "dict"
    if is_object_map(obj_state):
        _module_found, module_name_obj = map_get(obj_state, "__module_name__")
        if isinstance(module_name_obj, str) and module_name_obj:
            return module_name_obj
    return "unknown"


def _registered_object_attribute_result(
    state: VMState,
    obj: SymbolicObject,
    obj_state: object | None,
    attr_name: str,
    type_name: str,
    *,
    push_null: bool,
) -> ObjectAttributeLoad | None:
    """Return a model-registry attribute result for heap-backed symbolic objects."""
    if type_name == "unknown":
        return None
    model_name = f"{type_name}.{attr_name}"
    if not RuntimeModelRegistry.default().resolve(model_name):
        return None
    res_val = modeled_attribute_carrier(f"{getattr(obj, 'name', 'obj')}.{attr_name}")
    res_val.model_name = model_name
    state = state.push(res_val)
    if push_null:
        state = state.push(obj)
    state = state.advance_pc()
    return ObjectAttributeLoad(
        state=state,
        result_val=None,
        obj_state=obj_state,
        type_name=type_name,
        immediate_result=OpcodeResult.continue_with(state),
    )


def _load_direct_heap_object_attribute(
    state: VMState,
    obj: SymbolicObject,
    attr_name: str,
    *,
    push_null: bool,
) -> ObjectAttributeLoad:
    """Load an attribute from a precise heap address."""
    obj_state: object | None = state.load_heap(obj.address)
    if obj_state is None:
        obj_state = {}
        state = state.store_heap(obj.address, obj_state)
    type_name = _object_state_type_name(obj_state)
    registry_result = _registered_object_attribute_result(
        state,
        obj,
        obj_state,
        attr_name,
        type_name,
        push_null=push_null,
    )
    if registry_result is not None:
        return registry_result

    found_attr, raw_attr_value = (
        map_get(obj_state, attr_name) if is_object_map(obj_state) else (False, None)
    )
    if found_attr:
        result_val = coerce_call_stack_value(bind_heap_modeled_method(raw_attr_value, obj))
    else:
        result_val, type_constraint = SymbolicValue.symbolic(f"{obj.name}.{attr_name}")
        if is_object_map(obj_state):
            map_set(obj_state, attr_name, result_val)
            state = state.store_heap(obj.address, map_to_stack_dict(obj_state))
        state = state.add_constraint(type_constraint)
    return ObjectAttributeLoad(
        state=state,
        result_val=result_val,
        obj_state=obj_state,
        type_name=type_name,
    )


def _load_potential_address_attribute(
    state: VMState,
    obj: SymbolicObject,
    addr: int,
    attr_name: str,
) -> tuple[VMState, object]:
    """Load or create one potential-address attribute value."""
    mem_obj = state.load_heap(addr)
    found_attr, raw_attr_value = (
        map_get(mem_obj, attr_name) if is_object_map(mem_obj) else (False, None)
    )
    if found_attr:
        return state, coerce_call_stack_value(bind_heap_modeled_method(raw_attr_value, obj))
    val, _ = SymbolicValue.symbolic(f"obj_{addr}.{attr_name}")
    if is_object_map(mem_obj):
        map_set(mem_obj, attr_name, val)
        state = state.store_heap(addr, map_to_stack_dict(mem_obj))
    else:
        state = state.store_heap(addr, {attr_name: val})
    return state, val


def _merged_potential_address_attribute(
    obj: SymbolicObject,
    attr_name: str,
    values: list[tuple[object, object]],
) -> object:
    """Merge possible heap-address attribute values by symbolic address condition."""
    if len(values) == 1:
        return values[0][1]
    _base_addr, base_val = values[-1]
    if not isinstance(base_val, SymbolicValue):
        base_val = SymbolicValue.from_const(base_val)
    merged_z3_int = base_val.z3_int
    merged_z3_bool = base_val.z3_bool
    merged_is_int = base_val.is_int
    merged_is_bool = base_val.is_bool
    for addr, val in reversed(values[:-1]):
        if not isinstance(val, SymbolicValue):
            val = SymbolicValue.from_const(val)
        cond = obj.z3_addr == addr
        merged_z3_int = z3.If(cond, val.z3_int, merged_z3_int)
        merged_z3_bool = z3.If(cond, val.z3_bool, merged_z3_bool)
        merged_is_int = z3.If(cond, val.is_int, merged_is_int)
        merged_is_bool = z3.If(cond, val.is_bool, merged_is_bool)
    return SymbolicValue(
        _name=f"{obj.name}.{attr_name}",
        z3_int=merged_z3_int,
        is_int=merged_is_int,
        z3_bool=merged_z3_bool,
        is_bool=merged_is_bool,
    )


def load_symbolic_object_attribute(
    state: VMState,
    obj: SymbolicObject,
    attr_name: str,
    *,
    push_null: bool,
) -> ObjectAttributeLoad:
    """Resolve attributes stored in heap-backed symbolic objects."""
    if obj.address != -1:
        return _load_direct_heap_object_attribute(
            state,
            obj,
            attr_name,
            push_null=push_null,
        )

    addresses = list(obj.potential_addresses)
    if not addresses:
        result_val, type_constraint = SymbolicValue.symbolic(f"{obj.name}.{attr_name}")
        state = state.add_constraint(type_constraint)
        return ObjectAttributeLoad(
            state=state,
            result_val=result_val,
            obj_state=None,
            type_name="unknown",
        )

    values: list[tuple[object, object]] = []
    for addr in addresses:
        state, val = _load_potential_address_attribute(state, obj, addr, attr_name)
        values.append((addr, val))
    return ObjectAttributeLoad(
        state=state,
        result_val=_merged_potential_address_attribute(obj, attr_name, values),
        obj_state=None,
        type_name="unknown",
    )
