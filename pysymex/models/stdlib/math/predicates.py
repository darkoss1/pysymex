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

"""Predicate math models."""

from __future__ import annotations

import math as _math
from typing import TYPE_CHECKING, Any, cast

import z3

from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


class MathIsfiniteModel(FunctionModel):
    """Model for math.isfinite()."""

    name = "isfinite"
    qualname = "math.isfinite"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"isfinite_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint, result.is_bool],
                side_effects={
                    "raised_exception": {
                        "issue_kind": "TYPE_ERROR",
                        "exception_type": "TypeError",
                        "message": "isfinite() takes exactly one argument (0 given)",
                        "source": "math.isfinite",
                    }
                },
            )
        if len(args) > 1:
            result, constraint = SymbolicValue.symbolic(f"isfinite_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint, result.is_bool],
                side_effects={
                    "raised_exception": {
                        "issue_kind": "TYPE_ERROR",
                        "exception_type": "TypeError",
                        "message": f"isfinite() takes exactly one argument ({len(args)} given)",
                        "source": "math.isfinite",
                    }
                },
            )

        x = args[0]
        if not isinstance(x, SymbolicValue):
            try:
                val = _math.isfinite(cast(Any, x))
                return ModelResult(value=SymbolicValue.from_const(val))
            except TypeError as exc:
                result, constraint = SymbolicValue.symbolic(f"isfinite_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.is_bool],
                    side_effects={
                        "raised_exception": {
                            "issue_kind": "TYPE_ERROR",
                            "exception_type": "TypeError",
                            "message": str(exc),
                            "source": "math.isfinite",
                        }
                    },
                )

        result, constraint = SymbolicValue.symbolic(f"isfinite_{state.pc}")
        type_error_cond = z3.Not(z3.Or(x.is_float, x.is_int, x.is_bool))
        is_finite_expr = z3.Or(
            x.is_int,
            x.is_bool,
            z3.And(
                x.is_float,
                z3.Not(z3.fpIsNaN(x.z3_float)),
                z3.Not(z3.fpIsInf(x.z3_float)),
            ),
        )
        return ModelResult(
            value=result,
            constraints=[
                constraint,
                result.is_bool,
                z3.Implies(z3.Not(type_error_cond), result.z3_bool == is_finite_expr),
            ],
            side_effects={
                "potential_exception": {
                    "type": "TypeError",
                    "message": "must be real number, not symbolic",
                    "condition": type_error_cond,
                }
            },
        )


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
            and not isinstance(args[0], SymbolicValue)
            and not isinstance(args[1], SymbolicValue)
        ):
            try:
                rel_tol_val = kwargs.get("rel_tol", 1e-09)
                abs_tol_val = kwargs.get("abs_tol", 0.0)
                if not isinstance(rel_tol_val, SymbolicValue) and not isinstance(
                    abs_tol_val, SymbolicValue
                ):
                    return ModelResult(
                        value=SymbolicValue.from_const(
                            _math.isclose(
                                cast(Any, args[0]),
                                cast(Any, args[1]),
                                rel_tol=cast(Any, rel_tol_val),
                                abs_tol=cast(Any, abs_tol_val),
                            )
                        )
                    )
            except Exception:
                pass

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
            result, constraint = SymbolicValue.symbolic(f"isinf_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint, result.is_bool],
                side_effects={
                    "raised_exception": {
                        "issue_kind": "TYPE_ERROR",
                        "exception_type": "TypeError",
                        "message": "isinf() takes exactly one argument (0 given)",
                        "source": "math.isinf",
                    }
                },
            )
        if len(args) > 1:
            result, constraint = SymbolicValue.symbolic(f"isinf_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint, result.is_bool],
                side_effects={
                    "raised_exception": {
                        "issue_kind": "TYPE_ERROR",
                        "exception_type": "TypeError",
                        "message": f"isinf() takes exactly one argument ({len(args)} given)",
                        "source": "math.isinf",
                    }
                },
            )

        x = args[0]
        if not isinstance(x, SymbolicValue):
            try:
                val = _math.isinf(cast(Any, x))
                return ModelResult(value=SymbolicValue.from_const(val))
            except TypeError as exc:
                result, constraint = SymbolicValue.symbolic(f"isinf_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.is_bool],
                    side_effects={
                        "raised_exception": {
                            "issue_kind": "TYPE_ERROR",
                            "exception_type": "TypeError",
                            "message": str(exc),
                            "source": "math.isinf",
                        }
                    },
                )

        result, constraint = SymbolicValue.symbolic(f"isinf_{state.pc}")
        type_error_cond = z3.Not(z3.Or(x.is_float, x.is_int, x.is_bool))
        is_inf_expr = z3.And(x.is_float, z3.fpIsInf(x.z3_float))
        return ModelResult(
            value=result,
            constraints=[
                constraint,
                result.is_bool,
                z3.Implies(z3.Not(type_error_cond), result.z3_bool == is_inf_expr),
            ],
            side_effects={
                "potential_exception": {
                    "type": "TypeError",
                    "message": "must be real number, not symbolic",
                    "condition": type_error_cond,
                }
            },
        )


class MathIsnanModel(FunctionModel):
    """Model for math.isnan()."""

    name = "isnan"
    qualname = "math.isnan"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"isnan_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint, result.is_bool],
                side_effects={
                    "raised_exception": {
                        "issue_kind": "TYPE_ERROR",
                        "exception_type": "TypeError",
                        "message": "isnan() takes exactly one argument (0 given)",
                        "source": "math.isnan",
                    }
                },
            )
        if len(args) > 1:
            result, constraint = SymbolicValue.symbolic(f"isnan_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint, result.is_bool],
                side_effects={
                    "raised_exception": {
                        "issue_kind": "TYPE_ERROR",
                        "exception_type": "TypeError",
                        "message": f"isnan() takes exactly one argument ({len(args)} given)",
                        "source": "math.isnan",
                    }
                },
            )

        x = args[0]
        if not isinstance(x, SymbolicValue):
            try:
                val = _math.isnan(cast(Any, x))
                return ModelResult(value=SymbolicValue.from_const(val))
            except TypeError as exc:
                result, constraint = SymbolicValue.symbolic(f"isnan_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.is_bool],
                    side_effects={
                        "raised_exception": {
                            "issue_kind": "TYPE_ERROR",
                            "exception_type": "TypeError",
                            "message": str(exc),
                            "source": "math.isnan",
                        }
                    },
                )

        result, constraint = SymbolicValue.symbolic(f"isnan_{state.pc}")
        type_error_cond = z3.Not(z3.Or(x.is_float, x.is_int, x.is_bool))
        is_nan_expr = z3.And(x.is_float, z3.fpIsNaN(x.z3_float))
        return ModelResult(
            value=result,
            constraints=[
                constraint,
                result.is_bool,
                z3.Implies(z3.Not(type_error_cond), result.z3_bool == is_nan_expr),
            ],
            side_effects={
                "potential_exception": {
                    "type": "TypeError",
                    "message": "must be real number, not symbolic",
                    "condition": type_error_cond,
                }
            },
        )


__all__ = ["MathIsfiniteModel", "MathIsCloseModel", "MathIsinfModel", "MathIsnanModel"]
