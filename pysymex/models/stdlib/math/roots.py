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

"""Root and rounding math models."""

from __future__ import annotations

import math as _math
from typing import TYPE_CHECKING, Any, cast

import z3

from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins import FunctionModel, ModelResult
from pysymex.models.builtins.base import SideEffectValue

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


def _value_error_side_effect(source: str, message: str) -> dict[str, SideEffectValue]:
    return {
        "raised_exception": {
            "issue_kind": "VALUE_ERROR",
            "exception_type": "ValueError",
            "message": message,
            "source": source,
        }
    }


def _potential_value_error_side_effect(
    condition: z3.BoolRef, message: str
) -> dict[str, SideEffectValue]:
    return {
        "potential_exception": {
            "type": "ValueError",
            "message": message,
            "condition": condition,
        }
    }


def _sqrt_negative_condition(value: SymbolicValue) -> z3.BoolRef:
    return z3.Or(
        z3.And(value.is_int, value.z3_int < 0),
        z3.And(value.is_float, z3.fpLT(value.z3_float, z3.FPVal(0.0, z3.Float64()))),
    )


class MathSqrtModel(FunctionModel):
    """Model for math.sqrt()."""

    name = "sqrt"
    qualname = "math.sqrt"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"sqrt_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        if isinstance(x, (int, float)):
            try:
                return ModelResult(value=SymbolicValue.from_const(_math.sqrt(x)))
            except ValueError as exc:
                result, constraint = SymbolicValue.symbolic(f"sqrt_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.is_float],
                    side_effects=_value_error_side_effect("math.sqrt", str(exc)),
                )
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"sqrt_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_float,
                    z3.Or(
                        z3.And(x.is_float, z3.fpGEQ(x.z3_float, z3.FPVal(0.0, z3.Float64()))),
                        z3.And(x.is_int, x.z3_int >= 0),
                    ),
                    result.z3_float
                    == z3.fpSqrt(
                        z3.RNE(),
                        z3.If(
                            x.is_float,
                            x.z3_float,
                            z3.fpToFP(z3.RNE(), z3.ToReal(x.z3_int), z3.Float64()),
                        ),
                    ),
                ],
                side_effects=_potential_value_error_side_effect(
                    _sqrt_negative_condition(x), "math domain error"
                ),
            )
        result, constraint = SymbolicValue.symbolic(f"sqrt_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_float])


class MathCeilModel(FunctionModel):
    """Model for math.ceil()."""

    name = "ceil"
    qualname = "math.ceil"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"ceil_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.is_int])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.ceil(x)))
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"ceil_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_int,
                    result.z3_int
                    == z3.If(
                        x.is_float,
                        z3.ToInt(z3.fpToReal(z3.fpRoundToIntegral(z3.RTP(), x.z3_float))),
                        x.z3_int,
                    ),
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"ceil_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class MathFloorModel(FunctionModel):
    """Model for math.floor()."""

    name = "floor"
    qualname = "math.floor"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"floor_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.is_int])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.floor(x)))
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"floor_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_int,
                    result.z3_int
                    == z3.If(
                        x.is_float,
                        z3.ToInt(z3.fpToReal(z3.fpRoundToIntegral(z3.RTN(), x.z3_float))),
                        x.z3_int,
                    ),
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"floor_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class MathFactorialModel(FunctionModel):
    """Model for math.factorial()."""

    name = "factorial"
    qualname = "math.factorial"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"factorial_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.is_int])
        x = args[0]
        if isinstance(x, (int, float)):
            try:
                if isinstance(x, float):
                    if not x.is_integer() or x < 0:
                        raise ValueError("factorial() only accepts integral values")
                    val = _math.factorial(int(x))
                else:
                    if x < 0:
                        raise ValueError("factorial() not defined for negative values")
                    val = _math.factorial(x)
                return ModelResult(value=SymbolicValue.from_const(val))
            except (ValueError, OverflowError) as exc:
                result, constraint = SymbolicValue.symbolic(f"factorial_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.is_int],
                    side_effects=_value_error_side_effect("math.factorial", str(exc)),
                )
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"factorial_{x.name}")
            n_int = z3.If(
                x.is_float,
                z3.ToInt(z3.fpToReal(x.z3_float)),
                x.z3_int,
            )
            exact_constraints = [
                z3.Implies(n_int == 0, result.z3_int == 1),
                z3.Implies(n_int == 1, result.z3_int == 1),
                z3.Implies(n_int == 2, result.z3_int == 2),
                z3.Implies(n_int == 3, result.z3_int == 6),
                z3.Implies(n_int == 4, result.z3_int == 24),
                z3.Implies(n_int == 5, result.z3_int == 120),
                z3.Implies(n_int == 6, result.z3_int == 720),
                z3.Implies(n_int == 7, result.z3_int == 5040),
                z3.Implies(n_int == 8, result.z3_int == 40320),
                z3.Implies(n_int > 8, result.z3_int > 40320),
            ]
            is_negative_int = z3.And(x.is_int, x.z3_int < 0)
            is_negative_float = z3.And(x.is_float, z3.fpLT(x.z3_float, z3.FPVal(0.0, z3.Float64())))
            is_non_integral_float = z3.And(
                x.is_float,
                z3.Or(
                    z3.fpIsNaN(x.z3_float),
                    z3.fpIsInf(x.z3_float),
                    x.z3_float != z3.fpRoundToIntegral(z3.RTN(), x.z3_float),
                ),
            )
            exc_cond = z3.Or(is_negative_int, is_negative_float, is_non_integral_float)
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_int,
                    z3.Implies(z3.Not(exc_cond), result.z3_int >= 1),
                ]
                + exact_constraints,
                side_effects=_potential_value_error_side_effect(
                    exc_cond, "factorial() only accepts integral values"
                ),
            )
        result, constraint = SymbolicValue.symbolic(f"factorial_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class MathTruncModel(FunctionModel):
    """Model for math.trunc()."""

    name = "trunc"
    qualname = "math.trunc"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if len(args) != 1:
            result, constraint = SymbolicValue.symbolic(f"trunc_{state.pc}")
            msg = (
                f"trunc() takes exactly one argument ({len(args)} given)"
                if args
                else "trunc() takes exactly one argument (0 given)"
            )
            return ModelResult(
                value=result,
                constraints=[constraint, result.is_int],
                side_effects={
                    "raised_exception": {
                        "issue_kind": "TYPE_ERROR",
                        "exception_type": "TypeError",
                        "message": msg,
                        "source": "math.trunc",
                    }
                },
            )

        x = args[0]
        if not isinstance(x, SymbolicValue):
            try:
                return ModelResult(value=SymbolicValue.from_const(_math.trunc(cast(Any, x))))
            except (TypeError, ValueError) as exc:
                result, constraint = SymbolicValue.symbolic(f"trunc_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.is_int],
                    side_effects={
                        "raised_exception": {
                            "issue_kind": "TYPE_ERROR"
                            if isinstance(exc, TypeError)
                            else "VALUE_ERROR",
                            "exception_type": type(exc).__name__,
                            "message": str(exc),
                            "source": "math.trunc",
                        }
                    },
                )

        result, constraint = SymbolicValue.symbolic(f"trunc_{x.name}")
        type_error_cond = z3.Not(z3.Or(x.is_float, x.is_int, x.is_bool))
        return ModelResult(
            value=result,
            constraints=[
                constraint,
                result.is_int,
                z3.Implies(
                    z3.Not(type_error_cond),
                    result.z3_int
                    == z3.If(
                        x.is_float,
                        z3.ToInt(z3.fpToReal(z3.fpRoundToIntegral(z3.RTZ(), x.z3_float))),
                        x.z3_int,
                    ),
                ),
            ],
            side_effects={
                "potential_exception": {
                    "type": "TypeError",
                    "message": "must be real number, not symbolic",
                    "condition": type_error_cond,
                }
            },
        )


__all__ = [
    "MathSqrtModel",
    "MathCeilModel",
    "MathFloorModel",
    "MathFactorialModel",
    "MathTruncModel",
]
