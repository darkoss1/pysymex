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

"""Copy and ordering symbolic bytearray models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.models.builtins.types.containers.bytes.shared import get_symbolic_bytes
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

from .exact import bytearray_literal, concrete_byte_items, replace_exact_bytearray

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class BytearrayReverseModel(FunctionModel):
    """Model for bytearray.reverse()."""

    name = "reverse"
    qualname = "bytearray.reverse"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(f"bytearray.{self.name}", state)
        b = get_symbolic_bytes(args[0], state) if args else None
        side_effects: dict[str, object] = {}
        if b is not None:
            items = b.concrete_items
            byte_items = concrete_byte_items(items) if items is not None else None
            if byte_items is not None:
                replace_exact_bytearray(b, list(reversed(byte_items)))
            side_effects["bytearray_mutation"] = {"operation": "reverse"}
        return ModelResult(value=SymbolicNoneType(), side_effects=side_effects)


class BytearrayCopyModel(FunctionModel):
    """Model for bytearray.copy()."""

    name = "copy"
    qualname = "bytearray.copy"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(f"bytearray.{self.name}", state)
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicList.symbolic(f"bytearray_copy_{state.pc}")
        constraints = [constraint]
        if b is not None:
            items = b.concrete_items
            byte_items = concrete_byte_items(items) if items is not None else None
            if byte_items is not None:
                return ModelResult(value=bytearray_literal(byte_items))
            constraints.append(result.z3_len == b.z3_len)
        return ModelResult(value=result, constraints=constraints)
