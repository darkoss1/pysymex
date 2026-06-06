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

"""Growth symbolic bytearray models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.models.builtins.core.iterator_items import iterator_exhaustion_side_effect

from ..shared import (
    FunctionModel,
    ModelResult,
    SymbolicNone,
    bytearray_type_error_result,
    get_symbolic_bytes,
    z3,
)
from .exact import (
    concrete_byte,
    concrete_byte_items,
    concrete_byte_values,
    concrete_index,
    replace_exact_bytearray,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


class BytearrayAppendModel(FunctionModel):
    """Model for bytearray.append(item)."""

    name = "append"
    qualname = "bytearray.append"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return bytearray_type_error_result(self.name, state)
        b = get_symbolic_bytes(args[0], state) if args else None
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        side_effects: dict[str, object] = {}
        if b is not None:
            old_len = b.z3_len
            byte_value = concrete_byte(args[1])
            if byte_value is not None:
                b.z3_array = z3.Store(b.z3_array, old_len, get_int_val(byte_value))
                items = b.concrete_items
                if items is not None:
                    setattr(b, "_concrete_items", [*items, byte_value])
            new_len = z3.Int(f"bytearray_len_{state.pc}")
            constraints.append(new_len == old_len + 1)
            b.z3_len = new_len
            side_effects["bytearray_mutation"] = {"operation": "append"}
        return ModelResult(value=SymbolicNone(), constraints=constraints, side_effects=side_effects)


class BytearrayExtendModel(FunctionModel):
    """Model for bytearray.extend(iterable)."""

    name = "extend"
    qualname = "bytearray.extend"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return bytearray_type_error_result(self.name, state)
        b = get_symbolic_bytes(args[0], state) if args else None
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        side_effects: dict[str, object] = {}
        if b is not None:
            old_len = b.z3_len
            extension = concrete_byte_values(args[1], state)
            new_len = z3.Int(f"bytearray_len_{state.pc}")
            if extension is not None:
                for offset, byte_value in enumerate(extension):
                    b.z3_array = z3.Store(b.z3_array, old_len + offset, get_int_val(byte_value))
                constraints.append(new_len == old_len + len(extension))
                items = b.concrete_items
                if items is not None:
                    setattr(b, "_concrete_items", [*items, *extension])
                iterator_side_effect = iterator_exhaustion_side_effect(args[1], state)
                if iterator_side_effect:
                    side_effects.update(iterator_side_effect)
            else:
                constraints.append(new_len >= old_len)
            b.z3_len = new_len
            side_effects["bytearray_mutation"] = {"operation": "extend"}
        return ModelResult(value=SymbolicNone(), constraints=constraints, side_effects=side_effects)


class BytearrayInsertModel(FunctionModel):
    """Model for bytearray.insert(index, item)."""

    name = "insert"
    qualname = "bytearray.insert"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 3 or kwargs:
            return bytearray_type_error_result(self.name, state)
        b = get_symbolic_bytes(args[0], state) if args else None
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        side_effects: dict[str, object] = {}
        if b is not None:
            items = b.concrete_items
            byte_items = concrete_byte_items(items) if items is not None else None
            index = concrete_index(args[1])
            byte_value = concrete_byte(args[2])
            if byte_items is not None and index is not None and byte_value is not None:
                updated = list(byte_items)
                updated.insert(_normalized_insert_index(index, len(updated)), byte_value)
                replace_exact_bytearray(b, updated)
            else:
                new_len = z3.Int(f"bytearray_len_{state.pc}")
                constraints.append(new_len == b.z3_len + 1)
                b.z3_len = new_len
            side_effects["bytearray_mutation"] = {"operation": "insert"}
        return ModelResult(value=SymbolicNone(), constraints=constraints, side_effects=side_effects)


def _normalized_insert_index(index: int, length: int) -> int:
    if index < 0:
        return max(index + length, 0)
    return min(index, length)
