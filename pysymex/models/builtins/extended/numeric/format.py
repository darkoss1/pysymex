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

"""Numeric formatting builtin models."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from ...base import FunctionModel, ModelResult
from ...core.helpers import type_error_side_effect, zero_division_error_side_effect


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


def _literal_integer(value: StackValue) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, SymbolicValue) and isinstance(value.value, int):
        return value.value
    return None


def _literal_number(value: StackValue) -> int | float | None:
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, SymbolicValue) and isinstance(value.value, (int, float)):
        return value.value
    return None


def _definite_invalid_integer_argument(value: StackValue) -> bool:
    if isinstance(value, (float, str, bytes, bytearray)):
        return True
    return isinstance(value, SymbolicValue) and isinstance(
        value.value, (float, str, bytes, bytearray)
    )


def _nonnegative_max_int(value: StackValue) -> int | None:
    max_value = getattr(value, "max_val", None)
    min_value = getattr(value, "min_val", None)
    if isinstance(min_value, int) and isinstance(max_value, int) and min_value >= 0:
        return max_value
    return None


def _hex_digit_upper_bound(max_value: int) -> int:
    return max(1, (max_value.bit_length() + 3) // 4)


def _oct_digit_upper_bound(max_value: int) -> int:
    return max(1, (max_value.bit_length() + 2) // 3)


class DivmodModel(FunctionModel):
    """Model for divmod()."""

    name = "divmod"
    qualname = "builtins.divmod"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return _arity_type_error("divmod", args, state)
        a: StackValue = args[0]
        b: StackValue = args[1]
        literal_a = _literal_number(a)
        literal_b = _literal_number(b)
        if literal_a is not None and literal_b is not None:
            try:
                q, r = divmod(literal_a, literal_b)
            except ZeroDivisionError as exc:
                quotient, c1 = SymbolicValue.symbolic(f"divmod_q_{state.pc}")
                remainder, c2 = SymbolicValue.symbolic(f"divmod_r_{state.pc}")
                return ModelResult(
                    value=(quotient, remainder),
                    constraints=[c1, c2],
                    side_effects=zero_division_error_side_effect("builtins.divmod", str(exc)),
                )
            return ModelResult(value=(SymbolicValue.from_const(q), SymbolicValue.from_const(r)))
        if isinstance(a, (int, float, bool, str, bytes, bytearray)) and isinstance(
            b, (int, float, bool, str, bytes, bytearray)
        ):
            quotient, c1 = SymbolicValue.symbolic(f"divmod_q_{state.pc}")
            remainder, c2 = SymbolicValue.symbolic(f"divmod_r_{state.pc}")
            return ModelResult(
                value=(quotient, remainder),
                constraints=[c1, c2],
                side_effects=type_error_side_effect(
                    "builtins.divmod", "divmod() operands do not support division"
                ),
            )
        if isinstance(a, SymbolicValue) and isinstance(b, SymbolicValue):
            quotient, c1 = SymbolicValue.symbolic(f"divmod_q_{state.pc}")
            remainder, c2 = SymbolicValue.symbolic(f"divmod_r_{state.pc}")
            return ModelResult(
                value=(quotient, remainder),
                constraints=[
                    c1,
                    c2,
                    quotient.is_int,
                    remainder.is_int,
                    a.z3_int == b.z3_int * quotient.z3_int + remainder.z3_int,
                    z3.If(
                        b.z3_int > 0,
                        z3.And(remainder.z3_int >= 0, remainder.z3_int < b.z3_int),
                        z3.And(remainder.z3_int <= 0, remainder.z3_int > b.z3_int),
                    ),
                    b.z3_int != 0,
                ],
            )
        quotient, c1 = SymbolicValue.symbolic(f"divmod_q_{state.pc}")
        remainder, c2 = SymbolicValue.symbolic(f"divmod_r_{state.pc}")
        return ModelResult(value=(quotient, remainder), constraints=[c1, c2])


class BinModel(FunctionModel):
    """Model for bin()."""

    name = "bin"
    qualname = "builtins.bin"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _arity_type_error("bin", args, state)
        value = args[0]
        literal = _literal_integer(value)
        if literal is not None:
            return ModelResult(value=SymbolicString.from_const(bin(literal)))
        if _definite_invalid_integer_argument(value):
            result, constraint = SymbolicString.symbolic(f"bin_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.bin", "bin() requires an integer argument"
                ),
            )
        result = _symbolic_format_string(f"bin_{state.pc}")
        constraints: list[z3.BoolRef] = []
        val: z3.ArithRef | None = getattr(value, "z3_int", None)
        if val is not None:
            constraints.append(result.z3_len >= 3)
            is_int = getattr(value, "is_int", None)
            if isinstance(is_int, z3.BoolRef) and z3.is_true(z3.simplify(is_int)):
                result = result.with_binary_integer_source(val)
        return ModelResult(value=result, constraints=constraints)


class OctModel(FunctionModel):
    """Model for oct()."""

    name = "oct"
    qualname = "builtins.oct"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _arity_type_error("oct", args, state)
        value = args[0]
        literal = _literal_integer(value)
        if literal is not None:
            return ModelResult(value=SymbolicString.from_const(oct(literal)))
        if _definite_invalid_integer_argument(value):
            result, constraint = SymbolicString.symbolic(f"oct_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.oct", "oct() requires an integer argument"
                ),
            )
        result, constraint = SymbolicString.symbolic(f"oct_{state.pc}")
        constraints: list[z3.BoolRef] = [constraint]
        val: z3.ArithRef | None = getattr(value, "z3_int", None)
        if val is not None:
            constraints.append(result.z3_len >= 3)
            max_value = _nonnegative_max_int(value)
            if max_value is not None:
                digit_upper_bound = _oct_digit_upper_bound(max_value)
                for digit in "1234567":
                    result = result.with_character_count_upper_bound(digit, digit_upper_bound)
        return ModelResult(value=result, constraints=constraints)


def _symbolic_format_string(name: str) -> SymbolicString:
    return SymbolicString(
        _name=name,
        _z3_str=z3.String(f"{name}_str"),
        _z3_len=z3.Int(f"{name}_len"),
    )


class HexModel(FunctionModel):
    """Model for hex()."""

    name = "hex"
    qualname = "builtins.hex"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _arity_type_error("hex", args, state)
        value = args[0]
        literal = _literal_integer(value)
        if literal is not None:
            return ModelResult(value=SymbolicString.from_const(hex(literal)))
        if _definite_invalid_integer_argument(value):
            result, constraint = SymbolicString.symbolic(f"hex_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.hex", "hex() requires an integer argument"
                ),
            )
        result, constraint = SymbolicString.symbolic(f"hex_{state.pc}")
        constraints: list[z3.BoolRef] = [constraint]
        val: z3.ArithRef | None = getattr(value, "z3_int", None)
        if val is not None:
            constraints.append(result.z3_len >= 3)
            max_value = _nonnegative_max_int(value)
            if max_value is not None:
                digit_upper_bound = _hex_digit_upper_bound(max_value)
                for digit in "123456789abcdef":
                    result = result.with_character_count_upper_bound(digit, digit_upper_bound)
        return ModelResult(value=result, constraints=constraints)
