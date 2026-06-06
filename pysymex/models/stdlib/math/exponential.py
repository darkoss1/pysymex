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

"""Logarithmic and exponential math models."""

from __future__ import annotations

import math as _math
from typing import TYPE_CHECKING

import z3

from pysymex.core.constants import Z3_TRUE
from pysymex.core.constants import Z3_FALSE
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins import FunctionModel, ModelResult
from pysymex.models.builtins.base import SideEffectValue

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


def _raised_exception_side_effect(
    issue_kind: str, exception_type: str, source: str, message: str
) -> dict[str, SideEffectValue]:
    return {
        "raised_exception": {
            "issue_kind": issue_kind,
            "exception_type": exception_type,
            "message": message,
            "source": source,
        }
    }


def _potential_exception_side_effect(
    exception_type: str, condition: z3.BoolRef, message: str
) -> dict[str, SideEffectValue]:
    return {
        "potential_exception": {
            "type": exception_type,
            "message": message,
            "condition": condition,
        }
    }


def _potential_exception_effect(
    exception_type: str, condition: z3.BoolRef, message: str
) -> dict[str, object]:
    return {
        "type": exception_type,
        "message": message,
        "condition": condition,
    }


def _log_nonpositive_condition(value: SymbolicValue) -> z3.BoolRef:
    return z3.Or(
        z3.And(value.is_int, value.z3_int <= 0),
        z3.And(value.is_float, z3.fpLEQ(value.z3_float, z3.FPVal(0.0, z3.Float64()))),
    )


def _log_base_one_condition(value: SymbolicValue) -> z3.BoolRef:
    return z3.Or(
        z3.And(value.is_int, value.z3_int == 1),
        z3.And(value.is_float, z3.fpEQ(value.z3_float, z3.FPVal(1.0, z3.Float64()))),
    )


def _exp_overflow_condition(value: SymbolicValue) -> z3.BoolRef:
    return z3.Or(
        z3.And(value.is_int, value.z3_int >= 710),
        z3.And(value.is_float, z3.fpGT(value.z3_float, z3.FPVal(709.782712893384, z3.Float64()))),
    )


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
        if isinstance(x, (int, float)) and (len(args) == 1 or isinstance(base, (int, float))):
            try:
                if len(args) == 1:
                    concrete = _math.log(x)
                elif isinstance(base, (int, float)):
                    concrete = _math.log(x, base)
                else:
                    concrete = None
                if concrete is None:
                    result, constraint = SymbolicValue.symbolic(f"log_{state.pc}")
                    return ModelResult(value=result, constraints=[constraint, result.is_float])
                return ModelResult(value=SymbolicValue.from_const(concrete))
            except ValueError as exc:
                result, constraint = SymbolicValue.symbolic(f"log_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.is_float],
                    side_effects=_raised_exception_side_effect(
                        "VALUE_ERROR", "ValueError", "math.log", str(exc)
                    ),
                )
            except ZeroDivisionError as exc:
                result, constraint = SymbolicValue.symbolic(f"log_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.is_float],
                    side_effects=_raised_exception_side_effect(
                        "DIVISION_BY_ZERO", "ZeroDivisionError", "math.log", str(exc)
                    ),
                )
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"log_{x.name}")
            value_error_condition = _log_nonpositive_condition(x)
            zero_division_condition: z3.BoolRef | None = None
            if len(args) > 1:
                if isinstance(base, SymbolicValue):
                    value_error_condition = z3.Or(
                        value_error_condition, _log_nonpositive_condition(base)
                    )
                    zero_division_condition = _log_base_one_condition(base)
                elif isinstance(base, (int, float)):
                    base_invalid = Z3_TRUE if base <= 0 else Z3_FALSE
                    value_error_condition = z3.Or(value_error_condition, base_invalid)
                    if base == 1:
                        zero_division_condition = Z3_TRUE
            side_effects: dict[str, SideEffectValue]
            if zero_division_condition is None:
                side_effects = _potential_exception_side_effect(
                    "ValueError", value_error_condition, "math domain error"
                )
            else:
                side_effects = {
                    "potential_exceptions": [
                        _potential_exception_effect(
                            "ValueError", value_error_condition, "math domain error"
                        ),
                        _potential_exception_effect(
                            "ZeroDivisionError",
                            zero_division_condition,
                            "float division by zero",
                        ),
                    ]
                }
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_float,
                    x.z3_int > 0,
                ],
                side_effects=side_effects,
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
            try:
                return ModelResult(value=SymbolicValue.from_const(_math.exp(x)))
            except OverflowError as exc:
                result, constraint = SymbolicValue.symbolic(f"exp_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.is_float],
                    side_effects=_raised_exception_side_effect(
                        "OVERFLOW", "OverflowError", "math.exp", str(exc)
                    ),
                )
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"exp_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_float,
                    z3.fpGT(result.z3_float, z3.FPVal(0.0, z3.Float64())),
                ],
                side_effects=_potential_exception_side_effect(
                    "OverflowError", _exp_overflow_condition(x), "math range error"
                ),
            )
        result, constraint = SymbolicValue.symbolic(f"exp_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_float])


__all__ = ["MathLogModel", "MathExpModel"]
