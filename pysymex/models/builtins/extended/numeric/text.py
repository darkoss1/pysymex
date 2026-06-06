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

"""Numeric and character builtin models."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

from pysymex.core.identity.addressing import next_address
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.typed_results import symbolic_int_result
from ...base import FunctionModel, ModelResult
from ...core.helpers import (
    type_error_side_effect,
    value_error_side_effect,
    zero_division_error_side_effect,
)


def _arity_type_error(name: str, args: list[StackValue], state: VMState) -> ModelResult:
    result, constraint = SymbolicValue.symbolic(f"{name}_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects=type_error_side_effect(
            f"builtins.{name}",
            f"{name}() received invalid positional argument count: {len(args)}",
        ),
    )


class OrdModel(FunctionModel):
    """Model for ord()."""

    name = "ord"
    qualname = "builtins.ord"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _arity_type_error("ord", args, state)
        val = args[0]
        if isinstance(val, (str, bytes, bytearray)):
            try:
                return ModelResult(value=SymbolicValue.from_const(ord(val)))
            except TypeError as exc:
                result, constraint = SymbolicValue.symbolic(f"ord_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.is_int],
                    side_effects=type_error_side_effect("builtins.ord", str(exc)),
                )
        if isinstance(val, SymbolicString):
            if z3.is_string_value(val.z3_str):
                try:
                    return ModelResult(value=SymbolicValue.from_const(ord(val.z3_str.as_string())))
                except TypeError as exc:
                    result, constraint = SymbolicValue.symbolic(f"ord_{state.pc}")
                    return ModelResult(
                        value=result,
                        constraints=[constraint, result.is_int],
                        side_effects=type_error_side_effect("builtins.ord", str(exc)),
                    )
            result, constraints = symbolic_int_result(f"ord_{state.pc}_{next_address()}")
            return ModelResult(
                value=result,
                constraints=[
                    *constraints,
                    val.z3_len == 1,
                    result.z3_int == z3.StrToCode(val.z3_str),
                    result.z3_int >= 0,
                    result.z3_int < 0x110000,
                ],
            )
        if isinstance(val, (int, float, bool)):
            result, constraint = SymbolicValue.symbolic(f"ord_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint, result.is_int],
                side_effects=type_error_side_effect(
                    "builtins.ord", "ord() expected a string of length 1"
                ),
            )
        result, constraint = SymbolicValue.symbolic(f"ord_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class ChrModel(FunctionModel):
    """Model for chr()."""

    name = "chr"
    qualname = "builtins.chr"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _arity_type_error("chr", args, state)
        val = args[0]
        if isinstance(val, int):
            try:
                return ModelResult(value=SymbolicString.from_const(chr(val)))
            except ValueError as exc:
                result, constraint = SymbolicString.symbolic(f"chr_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.z3_len == 1],
                    side_effects=value_error_side_effect("builtins.chr", str(exc)),
                )
        if isinstance(val, SymbolicValue):
            if isinstance(val.value, int):
                try:
                    return ModelResult(value=SymbolicString.from_const(chr(val.value)))
                except ValueError as exc:
                    result, constraint = SymbolicString.symbolic(f"chr_{state.pc}")
                    return ModelResult(
                        value=result,
                        constraints=[constraint, result.z3_len == 1],
                        side_effects=value_error_side_effect("builtins.chr", str(exc)),
                    )
            if isinstance(val.value, (float, str, bytes, bytearray)):
                result, constraint = SymbolicString.symbolic(f"chr_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.z3_len == 1],
                    side_effects=type_error_side_effect(
                        "builtins.chr", "chr() requires an integer argument"
                    ),
                )
            result, constraint = SymbolicString.symbolic(f"chr_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    val.z3_int >= 0,
                    val.z3_int < 0x110000,
                    result.z3_len == 1,
                ],
            )
        if isinstance(val, (str, bytes, bytearray, float)):
            result, constraint = SymbolicString.symbolic(f"chr_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint, result.z3_len == 1],
                side_effects=type_error_side_effect(
                    "builtins.chr", "chr() requires an integer argument"
                ),
            )
        result, constraint = SymbolicString.symbolic(f"chr_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_len == 1])


class PowModel(FunctionModel):
    """Model for pow()."""

    name = "pow"
    qualname = "builtins.pow"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if (
            len(args) > 3
            or set(kwargs) - {"base", "exp", "mod"}
            or (args and "base" in kwargs)
            or (len(args) > 1 and "exp" in kwargs)
            or (len(args) > 2 and "mod" in kwargs)
            or (not args and "base" not in kwargs)
            or (len(args) < 2 and "exp" not in kwargs)
        ):
            return _arity_type_error("pow", args, state)
        base: StackValue = args[0] if args else kwargs["base"]
        exp: StackValue = args[1] if len(args) > 1 else kwargs["exp"]
        mod: StackValue | None = args[2] if len(args) > 2 else kwargs.get("mod")
        if mod is not None and all(isinstance(value, int) for value in (base, exp, mod)):
            try:
                return ModelResult(
                    value=SymbolicValue.from_const(
                        pow(cast("int", base), cast("int", exp), cast("int", mod))
                    )
                )
            except ValueError as exc:
                result, constraint = SymbolicValue.symbolic(f"pow_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=value_error_side_effect("builtins.pow", str(exc)),
                )
        if mod is not None and all(
            isinstance(value, (int, float, bool, str, bytes, bytearray))
            for value in (base, exp, mod)
        ):
            result, constraint = SymbolicValue.symbolic(f"pow_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.pow", "pow() 3rd argument requires integer arguments"
                ),
            )
        if mod is None and isinstance(base, (int, float)) and isinstance(exp, (int, float)):
            try:
                return ModelResult(value=SymbolicValue.from_const(pow(base, exp)))
            except ZeroDivisionError as exc:
                result, constraint = SymbolicValue.symbolic(f"pow_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=zero_division_error_side_effect("builtins.pow", str(exc)),
                )
        if (
            mod is None
            and isinstance(base, (int, float, bool, str, bytes, bytearray))
            and isinstance(exp, (int, float, bool, str, bytes, bytearray))
        ):
            result, constraint = SymbolicValue.symbolic(f"pow_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect("builtins.pow", "pow() operands are invalid"),
            )
        result, constraint = SymbolicValue.symbolic(f"pow_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


def _round_type_error(state: VMState, message: str) -> ModelResult:
    result, constraint = SymbolicValue.symbolic(f"round_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects=type_error_side_effect("builtins.round", message),
    )


class RoundModel(FunctionModel):
    """Model for round()."""

    name = "round"
    qualname = "builtins.round"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if (
            len(args) > 2
            or set(kwargs) - {"number", "ndigits"}
            or (args and "number" in kwargs)
            or (len(args) > 1 and "ndigits" in kwargs)
            or (not args and "number" not in kwargs)
        ):
            return _arity_type_error("round", args, state)
        val = args[0] if args else kwargs["number"]
        raw_ndigits = args[1] if len(args) > 1 else kwargs.get("ndigits")
        if isinstance(raw_ndigits, SymbolicValue):
            if isinstance(raw_ndigits.value, int):
                raw_ndigits = raw_ndigits.value
            elif isinstance(raw_ndigits.value, (float, str, bytes, bytearray)):
                return _round_type_error(state, "round() ndigits must be an integer")
        if raw_ndigits is not None and not isinstance(raw_ndigits, int):
            if isinstance(raw_ndigits, (float, str, bytes, bytearray)):
                return _round_type_error(state, "round() ndigits must be an integer")
            result, constraint = SymbolicValue.symbolic(f"round_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        ndigits = raw_ndigits
        if isinstance(val, (int, float)):
            rounded_result: int | float = round(val, ndigits)
            return ModelResult(value=rounded_result)
        if isinstance(val, SymbolicValue):
            if isinstance(val.value, (int, float)):
                return ModelResult(value=round(val.value, ndigits))
            if val.affinity_type in {"str", "bytes"}:
                return _round_type_error(state, "round() requires a numeric argument")
            if isinstance(val.value, (str, bytes, bytearray)):
                return _round_type_error(state, "round() requires a numeric argument")
        if isinstance(val, (str, bytes, bytearray)):
            return _round_type_error(state, "round() requires a numeric argument")
        result, constraint = SymbolicValue.symbolic(f"round_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])
