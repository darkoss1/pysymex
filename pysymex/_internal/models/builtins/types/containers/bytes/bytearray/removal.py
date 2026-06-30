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

"""Removal symbolic bytearray models."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.sequence_precision import normalize_concrete_index
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.types.containers.bytes.shared import get_symbolic_bytes
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult, SideEffects

from .exact import concrete_byte, concrete_byte_items, concrete_index, replace_exact_bytearray

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class BytearrayPopModel(FunctionModel):
    """Model for bytearray.pop(index=-1)."""

    name = "pop"
    qualname = "bytearray.pop"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {1, 2} or kwargs:
            return ModelResult.method_type_error(f"bytearray.{self.name}", state)
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic_int(f"bytearray_pop_{state.pc}")
        constraints = [constraint, result.z3_int >= 0, result.z3_int <= 255]
        side_effects: dict[str, object] = {}
        if b is not None:
            items = b.concrete_items
            byte_items = concrete_byte_items(items) if items is not None else None
            index = concrete_index(args[1]) if len(args) == 2 else -1
            if byte_items is not None and index is not None:
                normalized = normalize_concrete_index(index, len(byte_items))
                if normalized is not None:
                    updated = list(byte_items)
                    popped = updated.pop(normalized)
                    replace_exact_bytearray(b, updated)
                    return ModelResult(
                        value=SymbolicValue.from_const(popped),
                        side_effects={"bytearray_mutation": {"operation": "pop"}},
                    )
            side_effects["potential_exception"] = {
                "type": "IndexError",
                "condition": b.z3_len == 0,
                "message": "pop from empty bytearray",
            }
            new_len = z3.Int(f"bytearray_len_{state.pc}")
            constraints.append(new_len == b.z3_len - 1)
            constraints.append(new_len >= 0)
            b.z3_len = new_len
            side_effects["bytearray_mutation"] = {"operation": "pop"}
        return ModelResult(value=result, constraints=constraints, side_effects=side_effects)


class BytearrayRemoveModel(FunctionModel):
    """Model for bytearray.remove(value)."""

    name = "remove"
    qualname = "bytearray.remove"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error(f"bytearray.{self.name}", state)
        b = get_symbolic_bytes(args[0], state) if args else None
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        side_effects: dict[str, object] = {
            "potential_exception": {
                "type": "ValueError",
                "condition": z3.Bool(f"bytearray_remove_missing_{state.pc}"),
                "message": "value not found in bytearray",
            },
        }
        if b is not None:
            items = b.concrete_items
            byte_items = concrete_byte_items(items) if items is not None else None
            byte_value = concrete_byte(args[1])
            if byte_items is not None and byte_value is not None:
                if byte_value not in byte_items:
                    return ModelResult(
                        value=SymbolicNoneType(),
                        side_effects=SideEffects.value_error(
                            "bytearray.remove",
                            "value not found in bytearray",
                        ),
                    )
                updated = list(byte_items)
                updated.remove(byte_value)
                replace_exact_bytearray(b, updated)
                return ModelResult(
                    value=SymbolicNoneType(),
                    side_effects={"bytearray_mutation": {"operation": "remove"}},
                )
            new_len = z3.Int(f"bytearray_len_{state.pc}")
            constraints.append(new_len == b.z3_len - 1)
            constraints.append(new_len >= 0)
            b.z3_len = new_len
            side_effects["bytearray_mutation"] = {"operation": "remove"}
        return ModelResult(
            value=SymbolicNoneType(),
            constraints=constraints,
            side_effects=side_effects,
        )


class BytearrayClearModel(FunctionModel):
    """Model for bytearray.clear()."""

    name = "clear"
    qualname = "bytearray.clear"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(f"bytearray.{self.name}", state)
        b = get_symbolic_bytes(args[0], state) if args else None
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if b is not None:
            replace_exact_bytearray(b, [])
        return ModelResult(
            value=SymbolicNoneType(),
            constraints=constraints,
            side_effects={"bytearray_mutation": {"operation": "clear"}} if b is not None else {},
        )
