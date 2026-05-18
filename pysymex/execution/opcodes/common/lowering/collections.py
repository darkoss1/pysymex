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

"""Lowering for collection opcodes.

This module keeps opcode handlers small while preserving concrete CPython
cases before falling back to symbolic formulas.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

import z3

from pysymex.core.memory.addressing import next_address
from pysymex.core.types import (
    SymbolicDict,
    SymbolicList,
    SymbolicObject,
)
from pysymex.core.types.containers import storage_int_expr
from pysymex.core.types.scalars import (
    Z3_FALSE,
    Z3_TRUE,
    SymbolicString,
    SymbolicValue,
)

if TYPE_CHECKING:
    from pysymex._typing import StackValue


def _empty_constraints() -> list[z3.BoolRef]:
    return []


def _empty_heap_updates() -> list[tuple[int, StackValue]]:
    return []


@dataclass(frozen=True, slots=True)
class LoweredValue:
    """Value plus constraints emitted while lowering an opcode."""

    value: StackValue
    constraints: list[z3.BoolRef] = field(default_factory=_empty_constraints)
    exception_condition: z3.BoolRef = Z3_FALSE
    heap_updates: list[tuple[int, StackValue]] = field(default_factory=_empty_heap_updates)


@dataclass(frozen=True, slots=True)
class LoweredListBuild:
    """Heap handle and storage emitted by BUILD_LIST."""

    handle: SymbolicObject
    storage: SymbolicList
    heap_updates: list[tuple[int, StackValue]] = field(default_factory=_empty_heap_updates)


class CollectionLowerer:
    """Translate Python collection operations to VM values and SMT formulas."""

    def __init__(self, pc: int):
        self.pc = pc

    def lower_subscript(self, container: object, index: StackValue) -> LoweredValue:
        """Lower a subscript operation while preserving concrete CPython cases."""

        concrete = self._lower_concrete_subscript(container, index)
        if concrete is not None:
            return concrete

        if isinstance(container, SymbolicList):
            concrete_items = container.concrete_items
            concrete_index = self._concrete_int_index(index)
            if concrete_items is not None and concrete_index is not None:
                try:
                    return LoweredValue(self._to_stack_value(concrete_items[concrete_index]))
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
            s_key = self._coerce_key(index)
            if s_key is not None:
                result, presence_check = container[s_key]
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
        return LoweredValue(result, constraints=[constraint])

    def build_list(self, items: list[StackValue]) -> LoweredListBuild:
        """Build a SymbolicList and return its handle and storage."""
        count = len(items)
        z3_len = z3.IntVal(count)
        z3_array = z3.Array(f"list_{self.pc}_arr", z3.IntSort(), z3.IntSort())
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
        obj_handle = SymbolicObject(f"list_{addr}", addr, z3.IntVal(addr), {addr})
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
                z3_len=z3.IntVal(count),
                _concrete_items=list(items),
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
                s_val = self._coerce_value(val)
                sym_dict = sym_dict.__setitem__(s_key, s_val)

        if items or expected_count is None:
            return LoweredValue(sym_dict)
        return LoweredValue(dataclasses.replace(sym_dict, z3_len=z3.IntVal(expected_count)))

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
            return LoweredValue(set_value)

        sym_val, constraint = SymbolicValue.symbolic(f"set_{self.pc}")
        sym_val.set_runtime_type("set")
        sym_val.is_none = Z3_FALSE
        return LoweredValue(sym_val, constraints=[constraint])

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
            expr = z3.If(s_val.z3_bool, z3.IntVal(1), z3.IntVal(0))
        else:
            expr = z3.If(
                s_val.is_int,
                s_val.z3_int,
                z3.If(
                    s_val.is_bool, z3.If(s_val.z3_bool, z3.IntVal(1), z3.IntVal(0)), z3.IntVal(0)
                ),
            )

        new_z3_str = z3.IntToStr(expr)
        return SymbolicString(
            _name=f"str({s_val.name})",
            _z3_str=new_z3_str,
            _z3_len=z3.Length(new_z3_str),
        )

    def _coerce_index(self, val: StackValue) -> SymbolicValue | None:
        if isinstance(val, SymbolicValue):
            return val
        if isinstance(val, (int, bool)):
            return SymbolicValue.from_const(int(val))
        return None

    def _coerce_key(self, val: StackValue) -> SymbolicString | None:
        if isinstance(val, SymbolicString):
            return val
        if isinstance(val, str):
            return SymbolicString.from_const(val)
        if isinstance(val, SymbolicValue):
            return SymbolicString(_name=val.name, _unified=val)
        return None

    def _coerce_value(self, val: StackValue) -> SymbolicValue:
        if isinstance(val, SymbolicValue):
            return val
        return SymbolicValue.from_const(val)

    def _element_address_or_int(
        self,
        item: StackValue,
        address_by_identity: dict[int, int],
    ) -> tuple[z3.ArithRef, list[tuple[int, StackValue]]]:
        if isinstance(item, SymbolicObject):
            return item.z3_addr, []
        if isinstance(item, (SymbolicList, SymbolicDict)):
            identity = id(item)
            existing_address = address_by_identity.get(identity)
            if existing_address is not None:
                return z3.IntVal(existing_address), []
            addr = next_address()
            address_by_identity[identity] = addr
            return z3.IntVal(addr), [(addr, item)]
        s_val = self._coerce_value(item)
        return storage_int_expr(s_val.z3_int, f"collection_{self.pc}_elem"), []

    def _to_int_val(self, name: str, expr: z3.ArithRef) -> SymbolicValue:
        return SymbolicValue(
            _name=name,
            z3_int=expr,
            is_int=Z3_TRUE,
            is_bool=Z3_FALSE,
            z3_bool=Z3_FALSE,
        )

    def _lower_concrete_subscript(
        self,
        container: object,
        index: StackValue,
    ) -> LoweredValue | None:
        if isinstance(container, (list, tuple, str, bytes)):
            concrete_container = cast("list[object] | tuple[object, ...] | str | bytes", container)
            concrete_index = self._concrete_int_index(index)
            if concrete_index is None:
                return None
            try:
                return LoweredValue(self._to_stack_value(concrete_container[concrete_index]))
            except IndexError:
                result, constraint = SymbolicValue.symbolic(f"subscr_error_{self.pc}")
                return LoweredValue(result, constraints=[constraint], exception_condition=Z3_TRUE)
            except TypeError:
                return None

        if isinstance(container, dict):
            concrete_mapping = cast("dict[object, object]", container)
            concrete_key = self._concrete_key(index)
            if concrete_key is None:
                return None
            try:
                return LoweredValue(self._to_stack_value(concrete_mapping[concrete_key]))
            except KeyError:
                result, constraint = SymbolicValue.symbolic(f"subscr_error_{self.pc}")
                return LoweredValue(result, constraints=[constraint], exception_condition=Z3_TRUE)
            except TypeError:
                return None

        return None

    def _concrete_int_index(self, index: StackValue) -> int | None:
        if isinstance(index, bool):
            return int(index)
        if isinstance(index, int):
            return index
        if isinstance(index, SymbolicValue) and z3.is_int_value(index.z3_int):
            return index.z3_int.as_long()
        return None

    def _concrete_key(self, key: StackValue) -> object | None:
        if isinstance(key, SymbolicString) and z3.is_string_value(key.z3_str):
            return key.z3_str.as_string()
        if isinstance(key, SymbolicValue):
            value = key.value
            if value is not None:
                return value
            if z3.is_string_value(key.z3_str):
                return key.z3_str.as_string()
            if z3.is_int_value(key.z3_int):
                return key.z3_int.as_long()
            return None
        if isinstance(key, (str, int, bool, bytes, float, type(None))):
            return key
        return None

    def _to_stack_value(self, value: object) -> StackValue:
        if value is None:
            return None
        if isinstance(
            value,
            (
                SymbolicValue,
                SymbolicString,
                SymbolicList,
                SymbolicDict,
                SymbolicObject,
                int,
                bool,
                str,
                float,
                bytes,
                type,
                list,
                dict,
                tuple,
            ),
        ):
            return cast("StackValue", value)
        if callable(value):
            return cast("StackValue", value)
        return SymbolicValue.from_const(value)
