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

"""Lower ``BUILD_*`` and container literals to symbolic heap objects and constraints.

:class:`CollectionLowerer` builds lists, tuples, dicts, and strings from stack segments,
preferring concrete CPython sequences when available and attaching Z3 length/cardinality
facts otherwise. Opcode handlers in :mod:`pysymex.execution.opcodes.common.collections`
call into this module before pushing results.

Limitations:
    Heterogeneous or deeply symbolic element types may use fresh symbols per element
    rather than precise element-wise semantics.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING, cast

import z3

from pysymex.core.identity.addressing import next_address
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.containers.helpers import storage_int_expr
from pysymex.core.constants import Z3_FALSE
from pysymex.core.constants import Z3_INT_SORT
from pysymex.core.constants import Z3_ONE
from pysymex.core.constants import Z3_TRUE
from pysymex.core.constants import Z3_ZERO
from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.opcodes.common.lowering.concrete_subscript import (
    concrete_int_index,
    lower_concrete_subscript,
    to_stack_value,
)
from pysymex.execution.opcodes.common.lowering.types import (
    UNSUPPORTED_SUBSCRIPT_ABSTRACTION,
    LoweredListBuild,
    LoweredValue,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue


class CollectionLowerer:
    """Translate Python collection operations to VM values and SMT formulas."""

    def __init__(self, pc: int):
        """Record the bytecode offset used for collection lowering."""
        self.pc = pc

    def lower_subscript(self, container: object, index: StackValue) -> LoweredValue:
        """Lower a subscript operation while preserving concrete CPython cases."""

        concrete = lower_concrete_subscript(self.pc, container, index)
        if concrete is not None:
            return concrete

        if isinstance(container, SymbolicList):
            concrete_items = container.concrete_items
            concrete_index = concrete_int_index(index)
            if concrete_items is not None and concrete_index is not None:
                try:
                    return LoweredValue(to_stack_value(concrete_items[concrete_index]))
                except IndexError:
                    result, constraint = SymbolicValue.symbolic(f"subscr_error_{self.pc}")
                    return LoweredValue(
                        result,
                        constraints=[constraint],
                        exception_condition=Z3_TRUE,
                    )

            s_idx = self._coerce_index(index)
            if s_idx is not None:
                bounds_check = z3.And(
                    s_idx.z3_int >= -container.z3_len,
                    s_idx.z3_int < container.z3_len,
                )
                return LoweredValue(container[s_idx], exception_condition=z3.Not(bounds_check))

        if isinstance(container, SymbolicDict):
            concrete_presence = container.concrete_key_presence_condition(index)
            if concrete_presence is not None:
                has_value, concrete_value = container.concrete_value_for_key(index)
                if has_value:
                    return LoweredValue(to_stack_value(concrete_value))
                concrete_items_obj = getattr(container, "_concrete_items", None)
                if isinstance(concrete_items_obj, dict):
                    concrete_items = cast("dict[object, object]", concrete_items_obj)
                    if len(concrete_items) == 1:
                        concrete_value = next(iter(concrete_items.values()))
                        return LoweredValue(
                            to_stack_value(concrete_value),
                            exception_condition=z3.Not(concrete_presence),
                        )
                result, constraint = SymbolicValue.symbolic(f"{container.name}[{self.pc}]")
                return LoweredValue(
                    result,
                    constraints=[constraint],
                    exception_condition=z3.Not(concrete_presence),
                )

            s_key = self._coerce_key(index)
            if s_key is not None:
                result, presence_check = container[s_key]
                if getattr(container, "_value_type", None) == "dict":
                    result, constraint = self._nested_symbolic_dict(container, s_key)
                    return LoweredValue(
                        result,
                        constraints=[constraint],
                        exception_condition=z3.Not(presence_check),
                    )
                return LoweredValue(result, exception_condition=z3.Not(presence_check))

        if isinstance(container, SymbolicString):
            s_idx = self._coerce_index(index)
            if s_idx is not None:
                bounds_check = z3.And(
                    s_idx.z3_int >= -container.z3_len,
                    s_idx.z3_int < container.z3_len,
                )
                real_idx = z3.If(s_idx.z3_int < 0, s_idx.z3_int + container.z3_len, s_idx.z3_int)
                char_str = container.substring(
                    self._to_int_val(f"idx_{self.pc}", real_idx),
                    self._to_int_val(f"idx_plus_1_{self.pc}", real_idx + 1),
                )
                return LoweredValue(char_str, exception_condition=z3.Not(bounds_check))

        result, constraint = SymbolicValue.symbolic(f"subscr_havoc_{self.pc}")
        return LoweredValue(
            result,
            constraints=[constraint],
            degraded_passes=[UNSUPPORTED_SUBSCRIPT_ABSTRACTION],
        )

    def build_list(self, items: list[StackValue]) -> LoweredListBuild:
        """Build a SymbolicList and return its handle and storage."""
        count = len(items)
        z3_len = get_int_val(count)
        z3_array = z3.Array(f"list_{self.pc}_arr", Z3_INT_SORT, Z3_INT_SORT)
        heap_updates: list[tuple[int, StackValue]] = []
        address_by_identity: dict[int, int] = {}

        for i, item in enumerate(items):
            val_to_store, item_heap_updates = self._element_address_or_int(
                item, address_by_identity
            )
            heap_updates.extend(item_heap_updates)
            z3_array = z3.Store(z3_array, i, val_to_store)

        sym_list = SymbolicList(
            f"list_{self.pc}",
            z3_array=z3_array,
            z3_len=z3_len,
            element_type="any",
            _concrete_items=list(items),
        )

        addr = next_address()
        obj_handle = SymbolicObject(f"list_{addr}", addr, get_int_val(addr), {addr})
        return LoweredListBuild(obj_handle, sym_list, heap_updates)

    def build_tuple(self, items: list[StackValue]) -> LoweredValue:
        """Build a SymbolicList (immutable variant) and return storage."""
        count = len(items)
        sym_list = SymbolicList.empty(f"tuple_{self.pc}")
        z3_array = sym_list.z3_array
        heap_updates: list[tuple[int, StackValue]] = []
        address_by_identity: dict[int, int] = {}
        for i, item in enumerate(items):
            val_to_store, item_heap_updates = self._element_address_or_int(
                item, address_by_identity
            )
            heap_updates.extend(item_heap_updates)
            z3_array = z3.Store(z3_array, i, val_to_store)

        return LoweredValue(
            value=dataclasses.replace(
                sym_list,
                z3_array=z3_array,
                z3_len=get_int_val(count),
                _concrete_items=list(items),
                _type="tuple",
            ),
            heap_updates=heap_updates,
        )

    def build_map(
        self,
        items: list[tuple[StackValue, StackValue]],
        expected_count: int | None = None,
    ) -> LoweredValue:
        """Build a SymbolicDict from key-value pairs."""
        sym_dict = SymbolicDict.empty(f"dict_{self.pc}")
        sym_dict = dataclasses.replace(sym_dict, _concrete_items={})
        for key, val in items:
            s_key = self._coerce_key(key)
            if s_key is not None:
                sym_dict = sym_dict.__setitem__(key, val)

        if items or expected_count is None:
            return LoweredValue(sym_dict)
        return LoweredValue(dataclasses.replace(sym_dict, z3_len=get_int_val(expected_count)))

    def build_set(self, items: list[StackValue]) -> LoweredValue:
        """Build a symbolic set (represented as SymbolicValue for now)."""
        concrete_items: list[object] = []
        can_materialize = True
        for item in items:
            if isinstance(item, SymbolicValue):
                item_value = item.value
                if item_value is None:
                    can_materialize = False
                else:
                    concrete_items.append(item_value)
            else:
                concrete_items.append(item)

        if can_materialize:
            try:
                materialized = set(concrete_items)
            except TypeError:
                result, constraint = SymbolicValue.symbolic(f"set_error_{self.pc}")
                return LoweredValue(result, constraints=[constraint], exception_condition=Z3_TRUE)

            set_value = SymbolicValue.from_const(materialized)
            set_value.set_runtime_type("set")
            set_value.is_none = Z3_FALSE
            set_value.z3_int = get_int_val(len(materialized))
            setattr(set_value, "_hash_cache", None)
            return LoweredValue(set_value)

        sym_val, constraint = SymbolicValue.symbolic(f"set_{self.pc}")
        sym_val.set_runtime_type("set")
        sym_val.is_none = Z3_FALSE
        return LoweredValue(sym_val, constraints=[constraint])

    def _nested_symbolic_dict(
        self,
        container: SymbolicDict,
        key: SymbolicString,
    ) -> tuple[SymbolicDict, z3.BoolRef]:
        """Allocate a fresh symbolic nested dict for a missing key lookup."""
        nested, constraint = SymbolicDict.symbolic(f"{container.name}[{key.name}]")
        return nested, constraint

    def build_string(self, items: list[StackValue]) -> SymbolicString:
        """Concatenate symbolic strings and stringified symbolic values."""
        if not items:
            return SymbolicString.from_const("")

        result = None
        for item in items:
            part = self._stringify(item)
            if result is None:
                result = part
            else:
                result = result + part
        return cast("SymbolicString", result)

    def _stringify(self, val: StackValue) -> SymbolicString:
        """Coerce a stack value to :class:`SymbolicString` for literal building."""
        if isinstance(val, SymbolicString):
            return val
        if isinstance(val, str):
            return SymbolicString.from_const(val)

        s_val = self._coerce_value(val)
        concrete = s_val.value
        if concrete is not None:
            return SymbolicString.from_const(str(concrete))

        affinity = s_val.affinity_type
        if affinity == "int":
            expr = s_val.z3_int
        elif affinity == "bool":
            expr = z3.If(s_val.z3_bool, Z3_ONE, Z3_ZERO)
        else:
            expr = z3.If(
                s_val.is_int,
                s_val.z3_int,
                z3.If(
                    s_val.is_bool,
                    z3.If(s_val.z3_bool, Z3_ONE, Z3_ZERO),
                    Z3_ZERO,
                ),
            )

        new_z3_str = z3.IntToStr(expr)
        return SymbolicString(
            _name=f"str({s_val.name})",
            _z3_str=new_z3_str,
            _z3_len=z3.Length(new_z3_str),
        )

    def _coerce_index(self, val: StackValue) -> SymbolicValue | None:
        """Return a symbolic integer index when *val* is indexable."""
        if isinstance(val, SymbolicValue):
            return val
        if isinstance(val, (int, bool)):
            return SymbolicValue.from_const(int(val))
        return None

    def _coerce_key(self, val: StackValue) -> SymbolicString | None:
        """Return a symbolic string key when *val* can name a mapping entry."""
        if isinstance(val, SymbolicString):
            return val
        if isinstance(val, (str, int, bool, float)):
            return SymbolicString.from_const(str(val))
        if isinstance(val, SymbolicValue):
            return SymbolicString(_name=val.name, _unified=val)
        return None

    def _coerce_value(self, val: StackValue) -> SymbolicValue:
        """Wrap *val* as a :class:`SymbolicValue`."""
        if isinstance(val, SymbolicValue):
            return val
        return SymbolicValue.from_const(val)

    def _element_address_or_int(
        self,
        item: StackValue,
        address_by_identity: dict[int, int],
    ) -> tuple[z3.ArithRef, list[tuple[int, StackValue]]]:
        """Return heap address or Z3 int storage for a collection element."""
        if isinstance(item, SymbolicObject):
            return item.z3_addr, []
        if isinstance(item, (SymbolicList, SymbolicDict)):
            identity = id(item)
            existing_address = address_by_identity.get(identity)
            if existing_address is not None:
                return get_int_val(existing_address), []
            addr = next_address()
            address_by_identity[identity] = addr
            return get_int_val(addr), [(addr, item)]
        s_val = self._coerce_value(item)
        return storage_int_expr(s_val.z3_int, f"collection_{self.pc}_elem"), []

    def _to_int_val(self, name: str, expr: z3.ArithRef) -> SymbolicValue:
        """Build a :class:`SymbolicValue` wrapper around an arbitrary Z3 integer."""
        return SymbolicValue(
            _name=name,
            z3_int=expr,
            is_int=Z3_TRUE,
            is_bool=Z3_FALSE,
            z3_bool=Z3_FALSE,
        )
