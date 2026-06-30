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

"""Collection literal builders used by :class:`CollectionLowerer`."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_INT_SORT, Z3_TRUE
from pysymex._internal.core.identity.addressing import next_address
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.opcodes.common.lowering.collections.coercion import (
    CollectionCoercionMixin,
)
from pysymex._internal.execution.opcodes.common.lowering.types import (
    LoweredListBuild,
    LoweredValue,
)

if TYPE_CHECKING:
    from pysymex._internal.typing.protocols import StackValue


class BuildLoweringMixin(CollectionCoercionMixin):
    """Build symbolic collection values from stack segments."""

    def build_list(self, items: list[StackValue]) -> LoweredListBuild:
        """Build a SymbolicList and return its handle and storage."""
        count = len(items)
        z3_len = ConstraintValues.int(count)
        z3_array = z3.Array(f"list_{self.pc}_arr", Z3_INT_SORT, Z3_INT_SORT)
        heap_updates: list[tuple[int, StackValue]] = []
        address_by_identity: dict[int, int] = {}

        for i, item in enumerate(items):
            val_to_store, item_heap_updates = self._element_address_or_int(
                item,
                address_by_identity,
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
        obj_handle = SymbolicObject(f"list_{addr}", addr, ConstraintValues.int(addr), {addr})
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
                item,
                address_by_identity,
            )
            heap_updates.extend(item_heap_updates)
            z3_array = z3.Store(z3_array, i, val_to_store)

        return LoweredValue(
            value=dataclasses.replace(
                sym_list,
                z3_array=z3_array,
                z3_len=ConstraintValues.int(count),
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
        return LoweredValue(
            dataclasses.replace(sym_dict, z3_len=ConstraintValues.int(expected_count)),
        )

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
            set_value.z3_int = ConstraintValues.int(len(materialized))
            set_value.clear_hash_cache()
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
            result = part if result is None else result + part
        return cast("SymbolicString", result)
