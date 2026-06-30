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

import math
from typing import TYPE_CHECKING, Any, cast

import z3

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult, SideEffects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def _exception_result(
    result_name: str,
    result_type: str,
    source: str,
    exc: TypeError | ValueError | OverflowError,
) -> ModelResult:
    if result_type == "float":
        result, constraint = SymbolicValue.symbolic_float(result_name)
    elif result_type == "int":
        result, constraint = SymbolicValue.symbolic_int(result_name)
    elif result_type == "bool":
        result, constraint = SymbolicValue.symbolic_bool(result_name)
    else:
        result, constraint = SymbolicValue.symbolic(result_name)
    constraints = [constraint]

    issue_kind = "TYPE_ERROR" if isinstance(exc, TypeError) else "VALUE_ERROR"
    return ModelResult(
        value=result,
        constraints=constraints,
        side_effects=SideEffects.with_raised_exception(
            issue_kind,
            type(exc).__name__,
            source,
            str(exc),
        ),
    )


def _call_type_error(
    function: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> str:
    try:
        cast("Any", function)(*cast("Any", args), **cast("Any", kwargs))
    except TypeError as exc:
        return str(exc)
    except Exception:
        return f"{getattr(function, '__name__', 'function')}() received invalid arguments"
    return f"{getattr(function, '__name__', 'function')}() received invalid arguments"


def _wrong_arity_result(
    function: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    result_name: str,
    result_type: str,
    source: str,
) -> ModelResult:
    message = _call_type_error(function, args, kwargs)
    if result_type == "float":
        result, constraint = SymbolicValue.symbolic_float(result_name)
    elif result_type == "int":
        result, constraint = SymbolicValue.symbolic_int(result_name)
    else:
        result, constraint = SymbolicValue.symbolic(result_name)
    constraints = [constraint]
    return ModelResult(
        value=result,
        constraints=constraints,
        side_effects=SideEffects.type_error(source, message),
    )


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
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _wrong_arity_result(
                math.sqrt,
                args,
                kwargs,
                f"sqrt_{state.pc}",
                "float",
                "math.sqrt",
            )
        x = args[0]
        if not isinstance(x, SymbolicValue):
            try:
                return ModelResult(value=SymbolicValue.from_const(math.sqrt(cast("Any", x))))
            except (TypeError, ValueError) as exc:
                return _exception_result(f"sqrt_{state.pc}", "float", "math.sqrt", exc)
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
            side_effects={
                "potential_exception": SideEffects.potential_exception(
                    "ValueError",
                    "math domain error",
                    _sqrt_negative_condition(x),
                ),
            },
        )


class MathCeilModel(FunctionModel):
    """Model for math.ceil()."""

    name = "ceil"
    qualname = "math.ceil"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _wrong_arity_result(
                math.ceil,
                args,
                kwargs,
                f"ceil_{state.pc}",
                "int",
                "math.ceil",
            )
        x = args[0]
        if not isinstance(x, SymbolicValue):
            try:
                return ModelResult(value=SymbolicValue.from_const(math.ceil(cast("Any", x))))
            except TypeError as exc:
                return _exception_result(f"ceil_{state.pc}", "int", "math.ceil", exc)
        result, constraint = SymbolicValue.symbolic_int(f"ceil_{x.name}")
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


class MathFloorModel(FunctionModel):
    """Model for math.floor()."""

    name = "floor"
    qualname = "math.floor"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _wrong_arity_result(
                math.floor,
                args,
                kwargs,
                f"floor_{state.pc}",
                "int",
                "math.floor",
            )
        x = args[0]
        if not isinstance(x, SymbolicValue):
            try:
                return ModelResult(value=SymbolicValue.from_const(math.floor(cast("Any", x))))
            except TypeError as exc:
                return _exception_result(f"floor_{state.pc}", "int", "math.floor", exc)
        result, constraint = SymbolicValue.symbolic_int(f"floor_{x.name}")
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


class MathFactorialModel(FunctionModel):
    """Model for math.factorial()."""

    name = "factorial"
    qualname = "math.factorial"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _wrong_arity_result(
                math.factorial,
                args,
                kwargs,
                f"factorial_{state.pc}",
                "int",
                "math.factorial",
            )
        x = args[0]
        if not isinstance(x, SymbolicValue):
            try:
                return ModelResult(value=SymbolicValue.from_const(math.factorial(cast("Any", x))))
            except (TypeError, ValueError, OverflowError) as exc:
                return _exception_result(f"factorial_{state.pc}", "int", "math.factorial", exc)
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
                *exact_constraints,
            ],
            side_effects={
                "potential_exception": SideEffects.potential_exception(
                    "ValueError",
                    "factorial() only accepts integral values",
                    exc_cond,
                ),
            },
        )


class MathTruncModel(FunctionModel):
    """Model for math.trunc()."""

    name = "trunc"
    qualname = "math.trunc"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1:
            result, constraint = SymbolicValue.symbolic_int(f"trunc_{state.pc}")
            msg = (
                f"trunc() takes exactly one argument ({len(args)} given)"
                if args
                else "trunc() takes exactly one argument (0 given)"
            )
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects={
                    "raised_exception": {
                        "issue_kind": "TYPE_ERROR",
                        "exception_type": "TypeError",
                        "message": msg,
                        "source": "math.trunc",
                    },
                },
            )

        x = args[0]
        if not isinstance(x, SymbolicValue):
            try:
                return ModelResult(value=SymbolicValue.from_const(math.trunc(cast("Any", x))))
            except (TypeError, ValueError) as exc:
                result, constraint = SymbolicValue.symbolic_int(f"trunc_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects={
                        "raised_exception": {
                            "issue_kind": "TYPE_ERROR"
                            if isinstance(exc, TypeError)
                            else "VALUE_ERROR",
                            "exception_type": type(exc).__name__,
                            "message": str(exc),
                            "source": "math.trunc",
                        },
                    },
                )

        result, constraint = SymbolicValue.symbolic_int(f"trunc_{x.name}")
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
                },
            },
        )
