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

"""Shared helpers for symbolic string container models."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

get_symbolic_string = SymbolicString.resolve
concrete_string_literal = SymbolicString.concrete_literal

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def concrete_ascii_literal(arg: object) -> str | bytes | None:
    """Return exact str/bytes payloads for shared ASCII classification."""
    if isinstance(arg, (str, bytes)):
        return arg
    if isinstance(arg, SymbolicBytes):
        return arg.concrete_value
    if isinstance(arg, SymbolicString) and z3.is_string_value(arg.z3_str):
        return arg.z3_str.as_string()
    if isinstance(arg, SymbolicValue) and isinstance(arg.value, (str, bytes)):
        return arg.value
    if isinstance(arg, SymbolicList) and getattr(arg, "_type", None) == "bytes":
        items = arg.concrete_items
        if items is None:
            return None
        byte_values: list[int] = []
        for item in items:
            if not isinstance(item, int) or not 0 <= item <= 255:
                return None
            byte_values.append(item)
        return bytes(byte_values)
    return None


def _ascii_receiver_length(arg: object, state: VMState) -> z3.ArithRef | None:
    string_value = SymbolicString.resolve(arg)
    if string_value is not None:
        return string_value.z3_len
    if isinstance(arg, SymbolicBytes):
        return arg.z3_len
    bytes_value = SymbolicList.resolve_bytes(arg, state)
    if bytes_value is not None:
        return bytes_value.z3_len
    if isinstance(arg, SymbolicValue):
        return arg.symbolic_length()
    return None


def symbolic_isascii_result(arg: object, state: VMState) -> ModelResult:
    """Return the shared symbolic boolean result for isascii container models."""
    result, constraints = ModelResult.symbolic_bool(f"isascii_{state.pc}")
    receiver_length = _ascii_receiver_length(arg, state)
    if receiver_length is not None:
        constraints.append(z3.Implies(receiver_length == 0, result.z3_bool))
    return ModelResult(value=result, constraints=constraints)


class SymbolicIsasciiModel(FunctionModel):
    """Shared model implementation for str, bytes, and bytearray isascii."""

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        literal = concrete_ascii_literal(args[0])
        if literal is not None:
            return ModelResult(value=SymbolicValue.from_const(literal.isascii()))
        return symbolic_isascii_result(args[0], state)
