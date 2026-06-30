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

from pysymex._internal.models.contracts.results import SideEffects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

from pysymex._internal.core.identity.addressing import next_address
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult


def _arity_type_error(name: str, args: list[StackValue], state: VMState) -> ModelResult:
    result, constraint = SymbolicValue.symbolic(f"{name}_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects=SideEffects.type_error(
            f"builtins.{name}",
            f"{name}() received invalid positional argument count: {len(args)}",
        ),
    )


def _definite_builtin_pow_operand(value: StackValue | None) -> bool:
    """Return whether *value* has exact builtin power-protocol behavior."""
    return value is None or isinstance(
        value,
        (
            int,
            float,
            bool,
            str,
            bytes,
            bytearray,
            list,
            tuple,
            dict,
            set,
            frozenset,
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
                result, constraint = SymbolicValue.symbolic_int(f"ord_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=SideEffects.type_error("builtins.ord", str(exc)),
                )
        if isinstance(val, SymbolicString):
            if z3.is_string_value(val.z3_str):
                try:
                    return ModelResult(value=SymbolicValue.from_const(ord(val.z3_str.as_string())))
                except TypeError as exc:
                    result, constraint = SymbolicValue.symbolic_int(f"ord_{state.pc}")
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects=SideEffects.type_error("builtins.ord", str(exc)),
                    )
            result, constraints = ModelResult.symbolic_int(f"ord_{state.pc}_{next_address()}")
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
        if val is None or isinstance(val, (int, float, bool, list, tuple, dict, set, frozenset)):
            result, constraint = SymbolicValue.symbolic_int(f"ord_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.ord",
                    "ord() expected a string of length 1",
                ),
            )
        result, constraint = SymbolicValue.symbolic_int(f"ord_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


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
                    side_effects=SideEffects.value_error("builtins.chr", str(exc)),
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
                        side_effects=SideEffects.value_error("builtins.chr", str(exc)),
                    )
            if isinstance(
                val.value,
                (float, str, bytes, bytearray, list, tuple, dict, set, frozenset),
            ):
                result, constraint = SymbolicString.symbolic(f"chr_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.z3_len == 1],
                    side_effects=SideEffects.type_error(
                        "builtins.chr",
                        "chr() requires an integer argument",
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
        if val is None or isinstance(
            val,
            (str, bytes, bytearray, float, list, tuple, dict, set, frozenset),
        ):
            result, constraint = SymbolicString.symbolic(f"chr_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint, result.z3_len == 1],
                side_effects=SideEffects.type_error(
                    "builtins.chr",
                    "chr() requires an integer argument",
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
                        pow(cast("int", base), cast("int", exp), cast("int", mod)),
                    ),
                )
            except ValueError as exc:
                result, constraint = SymbolicValue.symbolic(f"pow_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=SideEffects.value_error("builtins.pow", str(exc)),
                )
        if mod is not None and all(
            _definite_builtin_pow_operand(value) for value in (base, exp, mod)
        ):
            result, constraint = SymbolicValue.symbolic(f"pow_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.pow",
                    "pow() 3rd argument requires integer arguments",
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
                    side_effects=SideEffects.zero_division_error("builtins.pow", str(exc)),
                )
        if mod is None and all(_definite_builtin_pow_operand(value) for value in (base, exp)):
            result, constraint = SymbolicValue.symbolic(f"pow_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error("builtins.pow", "pow() operands are invalid"),
            )
        result, constraint = SymbolicValue.symbolic(f"pow_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


def _round_type_error(state: VMState, message: str) -> ModelResult:
    result, constraint = SymbolicValue.symbolic(f"round_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects=SideEffects.type_error("builtins.round", message),
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
        if val is None or isinstance(
            val,
            (str, bytes, bytearray, list, tuple, dict, set, frozenset),
        ):
            return _round_type_error(state, "round() requires a numeric argument")
        result, constraint = SymbolicValue.symbolic(f"round_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])
