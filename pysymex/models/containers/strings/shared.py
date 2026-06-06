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

from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import FunctionModel, ModelResult
from pysymex.models.typed_results import model_bool_result, symbolic_int_result

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


def get_symbolic_string(arg: object) -> SymbolicString | None:
    """Extract SymbolicString from argument, handling method calls (self is first arg)."""
    if isinstance(arg, SymbolicString):
        return arg
    if isinstance(arg, str):
        return SymbolicString.from_const(arg)
    return None


def concrete_string_literal(arg: object) -> str | None:
    """Return a concrete Python string when a symbolic string value is exact."""
    if isinstance(arg, str):
        return arg
    if isinstance(arg, SymbolicString) and z3.is_string_value(arg.z3_str):
        return arg.z3_str.as_string()
    if isinstance(arg, SymbolicValue) and isinstance(arg.value, str):
        return arg.value
    return None


def concrete_ascii_literal(arg: object) -> str | bytes | None:
    """Return exact str/bytes payloads for shared ASCII classification."""
    if isinstance(arg, (str, bytes)):
        return arg
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


def symbolic_isascii_result(state: VMState) -> ModelResult:
    """Return the shared symbolic boolean result for isascii container models."""
    return model_bool_result(f"isascii_{state.pc}")


def method_type_error_result(qualname: str, state: VMState) -> ModelResult:
    """Return deterministic TypeError evidence for an invalid container method call."""
    result, constraint = SymbolicValue.symbolic(f"{qualname.replace('.', '_')}_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects={
            "raised_exception": {
                "issue_kind": "TYPE_ERROR",
                "exception_type": "TypeError",
                "message": f"{qualname}() received invalid arguments",
                "source": qualname,
            }
        },
    )


class SymbolicIsasciiModel(FunctionModel):
    """Shared model implementation for str, bytes, and bytearray isascii."""

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return method_type_error_result(self.qualname, state)
        literal = concrete_ascii_literal(args[0])
        if literal is not None:
            return ModelResult(value=SymbolicValue.from_const(literal.isascii()))
        return symbolic_isascii_result(state)


__all__ = [
    "FunctionModel",
    "ModelResult",
    "SymbolicIsasciiModel",
    "SymbolicList",
    "SymbolicString",
    "SymbolicValue",
    "concrete_ascii_literal",
    "concrete_string_literal",
    "get_symbolic_string",
    "method_type_error_result",
    "model_bool_result",
    "symbolic_int_result",
    "symbolic_isascii_result",
    "z3",
]
