# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Symbolic models for the math standard library module.

Models: sqrt, ceil, floor, log, exp, sin, cos, tan, fabs, gcd,
isfinite, isclose, isinf, isnan.
"""

from __future__ import annotations

import math as _math
from typing import TYPE_CHECKING

import z3

from pysymex.core.types import SymbolicValue
from pysymex.models.builtins import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState


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
        if isinstance(x, (int, float)) and x >= 0:
            return ModelResult(value=SymbolicValue.from_const(_math.sqrt(x)))
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"sqrt_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_float,
                    x.z3_int >= 0,
                    z3.fpGEQ(result.z3_float, z3.FPVal(0.0, z3.Float64())),
                ],
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
                    result.z3_int >= x.z3_int,
                    result.z3_int <= x.z3_int + 1,
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
                    result.z3_int <= x.z3_int,
                    result.z3_int >= x.z3_int - 1,
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"floor_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class MathLogModel(FunctionModel):
    """Model for math.log()."""

    name = "log"
    qualname = "math.log"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"log_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        base = args[1] if len(args) > 1 else _math.e
        if isinstance(x, (int, float)) and x > 0:
            if isinstance(base, (int, float)) and base > 0:
                return ModelResult(value=SymbolicValue.from_const(_math.log(x, base)))
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"log_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_float,
                    x.z3_int > 0,
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"log_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_float])


class MathExpModel(FunctionModel):
    """Model for math.exp()."""

    name = "exp"
    qualname = "math.exp"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"exp_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.exp(x)))
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"exp_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_float,
                    z3.fpGT(result.z3_float, z3.FPVal(0.0, z3.Float64())),
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"exp_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_float])


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
        return ModelResult(value=result, constraints=constraints)


class MathIsfiniteModel(FunctionModel):
    """Model for math.isfinite()."""

    name = "isfinite"
    qualname = "math.isfinite"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"isfinite_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.is_bool])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.isfinite(x)))
        if isinstance(x, SymbolicValue) and hasattr(x, "is_int"):
            result, constraint = SymbolicValue.symbolic(f"isfinite_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint, result.is_bool, result.z3_bool == x.is_int],
            )
        result, constraint = SymbolicValue.symbolic(f"isfinite_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class MathIsCloseModel(FunctionModel):
    """Model for math.isclose()."""

    name = "isclose"
    qualname = "math.isclose"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"isclose_{state.pc}")
        if (
            len(args) >= 2
            and isinstance(args[0], (int, float))
            and isinstance(args[1], (int, float))
        ):
            return ModelResult(value=SymbolicValue.from_const(_math.isclose(args[0], args[1])))

        constraints: list[z3.BoolRef] = [constraint, result.is_bool]
        if len(args) >= 2:
            a, b = args[0], args[1]

            rel_tol_val = kwargs.get("rel_tol", 1e-09)
            abs_tol_val = kwargs.get("abs_tol", 0.0)

            def get_fp(val: StackValue) -> z3.FPRef:
                if isinstance(val, (int, float)):
                    return z3.FPVal(float(val), z3.Float64())
                if isinstance(val, SymbolicValue):
                    return val.z3_float

                return z3.FPVal(0.0, z3.Float64())

            a_fp = get_fp(a)
            b_fp = get_fp(b)
            rel_fp = get_fp(rel_tol_val)
            abs_fp = get_fp(abs_tol_val)

            diff = z3.If(
                z3.fpGEQ(a_fp, b_fp), z3.fpSub(z3.RNE(), a_fp, b_fp), z3.fpSub(z3.RNE(), b_fp, a_fp)
            )

            a_abs = z3.If(z3.fpGEQ(a_fp, z3.FPVal(0.0, z3.Float64())), a_fp, z3.fpNeg(a_fp))
            b_abs = z3.If(z3.fpGEQ(b_fp, z3.FPVal(0.0, z3.Float64())), b_fp, z3.fpNeg(b_fp))
            max_ab = z3.If(z3.fpGEQ(a_abs, b_abs), a_abs, b_abs)

            rel_term = z3.fpMul(z3.RNE(), rel_fp, max_ab)
            tol = z3.If(z3.fpGT(rel_term, abs_fp), rel_term, abs_fp)

            constraints.append(result.z3_bool == z3.fpLEQ(diff, tol))

        return ModelResult(value=result, constraints=constraints)


class MathIsinfModel(FunctionModel):
    """Model for math.isinf()."""

    name = "isinf"
    qualname = "math.isinf"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if not args:
            return ModelResult(value=SymbolicValue.from_const(False))
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.isinf(x)))
        if isinstance(x, SymbolicValue):
            return ModelResult(value=SymbolicValue.from_const(False))
        result, constraint = SymbolicValue.symbolic(f"isinf_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class MathIsnanModel(FunctionModel):
    """Model for math.isnan()."""

    name = "isnan"
    qualname = "math.isnan"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if not args:
            return ModelResult(value=SymbolicValue.from_const(False))
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.isnan(x)))
        if isinstance(x, SymbolicValue):
            return ModelResult(value=SymbolicValue.from_const(False))
        result, constraint = SymbolicValue.symbolic(f"isnan_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


math_models = [
    MathSqrtModel(),
    MathCeilModel(),
    MathFloorModel(),
    MathLogModel(),
    MathExpModel(),
    MathSinModel(),
    MathCosModel(),
    MathTanModel(),
    MathFabsModel(),
    MathGcdModel(),
    MathIsfiniteModel(),
    MathIsinfModel(),
    MathIsnanModel(),
    MathIsCloseModel(),
]
