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

"""Trigonometric and numeric math models."""

from __future__ import annotations

import math as _math
from typing import TYPE_CHECKING

import z3

from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


class MathSinModel(FunctionModel):
    """Model for math.sin()."""

    name = "sin"
    qualname = "math.sin"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"sin_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.sin(x)))
        result, constraint = SymbolicValue.symbolic(f"sin_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[
                constraint,
                result.is_float,
                z3.fpGEQ(result.z3_float, z3.FPVal(-1.0, z3.Float64())),
                z3.fpLEQ(result.z3_float, z3.FPVal(1.0, z3.Float64())),
            ],
        )


class MathCosModel(FunctionModel):
    """Model for math.cos()."""

    name = "cos"
    qualname = "math.cos"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"cos_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.cos(x)))
        result, constraint = SymbolicValue.symbolic(f"cos_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[
                constraint,
                result.is_float,
                z3.fpGEQ(result.z3_float, z3.FPVal(-1.0, z3.Float64())),
                z3.fpLEQ(result.z3_float, z3.FPVal(1.0, z3.Float64())),
            ],
        )


class MathTanModel(FunctionModel):
    """Model for math.tan()."""

    name = "tan"
    qualname = "math.tan"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"tan_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.tan(x)))
        result, constraint = SymbolicValue.symbolic(f"tan_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_float])


class MathFabsModel(FunctionModel):
    """Model for math.fabs()."""

    name = "fabs"
    qualname = "math.fabs"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"fabs_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.fabs(x)))
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"fabs_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_float,
                    z3.fpGEQ(result.z3_float, z3.FPVal(0.0, z3.Float64())),
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"fabs_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[
                constraint,
                result.is_float,
                z3.fpGEQ(result.z3_float, z3.FPVal(0.0, z3.Float64())),
            ],
        )


class MathGcdModel(FunctionModel):
    """Model for math.gcd()."""

    name = "gcd"
    qualname = "math.gcd"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if len(args) < 2:
            result, constraint = SymbolicValue.symbolic(f"gcd_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.is_int])
        a, b = args[0], args[1]
        if isinstance(a, int) and isinstance(b, int):
            return ModelResult(value=SymbolicValue.from_const(_math.gcd(a, b)))
        result, constraint = SymbolicValue.symbolic(f"gcd_{state.pc}")
        constraints = [constraint, result.is_int, result.z3_int >= 0]
        if isinstance(a, SymbolicValue):
            constraints.append(result.z3_int <= z3.If(a.z3_int >= 0, a.z3_int, -a.z3_int))
        if isinstance(b, SymbolicValue):
            constraints.append(result.z3_int <= z3.If(b.z3_int >= 0, b.z3_int, -b.z3_int))
        a_expr = _gcd_int_expr(a)
        b_expr = _gcd_int_expr(b)
        if a_expr is not None and b_expr is not None:
            constraints.append((result.z3_int == 0) == z3.And(a_expr == 0, b_expr == 0))
        return ModelResult(value=result, constraints=constraints)


def _gcd_int_expr(value: object) -> z3.ArithRef | None:
    if isinstance(value, bool | int):
        return get_int_val(int(value))
    if isinstance(value, SymbolicValue):
        return value.z3_int
    return None


class MathRadiansModel(FunctionModel):
    """Model for math.radians()."""

    name = "radians"
    qualname = "math.radians"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"radians_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.radians(x)))
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"radians_{x.name}")
            x_fp = z3.If(
                x.is_float, x.z3_float, z3.fpToFP(z3.RNE(), z3.ToReal(x.z3_int), z3.Float64())
            )
            pi_div_180 = z3.FPVal(_math.pi / 180.0, z3.Float64())
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_float,
                    result.z3_float == z3.fpMul(z3.RNE(), x_fp, pi_div_180),
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"radians_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_float])


class MathDegreesModel(FunctionModel):
    """Model for math.degrees()."""

    name = "degrees"
    qualname = "math.degrees"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"degrees_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.degrees(x)))
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"degrees_{x.name}")
            x_fp = z3.If(
                x.is_float, x.z3_float, z3.fpToFP(z3.RNE(), z3.ToReal(x.z3_int), z3.Float64())
            )
            val_180_div_pi = z3.FPVal(180.0 / _math.pi, z3.Float64())
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_float,
                    result.z3_float == z3.fpMul(z3.RNE(), x_fp, val_180_div_pi),
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"degrees_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_float])


class MathCopysignModel(FunctionModel):
    """Model for math.copysign()."""

    name = "copysign"
    qualname = "math.copysign"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if len(args) < 2:
            result, constraint = SymbolicValue.symbolic(f"copysign_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.is_float])
        x, y = args[0], args[1]
        if isinstance(x, (int, float)) and isinstance(y, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.copysign(x, y)))
        if isinstance(x, SymbolicValue) or isinstance(y, SymbolicValue):
            x_sym = x if isinstance(x, SymbolicValue) else SymbolicValue.from_const(x)
            y_sym = y if isinstance(y, SymbolicValue) else SymbolicValue.from_const(y)
            result, constraint = SymbolicValue.symbolic(f"copysign_{state.pc}")
            x_fp = z3.If(
                x_sym.is_float,
                x_sym.z3_float,
                z3.fpToFP(z3.RNE(), z3.ToReal(x_sym.z3_int), z3.Float64()),
            )
            y_fp = z3.If(
                y_sym.is_float,
                y_sym.z3_float,
                z3.fpToFP(z3.RNE(), z3.ToReal(y_sym.z3_int), z3.Float64()),
            )
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_float,
                    result.z3_float
                    == z3.If(z3.fpIsNegative(y_fp), z3.fpNeg(z3.fpAbs(x_fp)), z3.fpAbs(x_fp)),
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"copysign_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_float])


__all__ = [
    "MathSinModel",
    "MathCosModel",
    "MathTanModel",
    "MathFabsModel",
    "MathGcdModel",
    "MathRadiansModel",
    "MathDegreesModel",
    "MathCopysignModel",
]
