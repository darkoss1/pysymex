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

"""Broad typed coverage for pure public :mod:`math` functions."""

from __future__ import annotations

import inspect
import math
from typing import TYPE_CHECKING, Literal, cast

import z3

from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelDegradation, ModelResult
from pysymex._internal.models.stdlib.literals import concrete_call, raised_exception, stack_value

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

ResultKind = Literal["float", "int", "numeric", "float_pair"]

_INT_RESULTS = {"comb", "isqrt", "lcm", "perm"}
_NUMERIC_RESULTS = {"prod", "sumprod"}
_FLOAT_PAIR_RESULTS = {"frexp", "modf"}
_FLOAT_BOUNDS: dict[str, tuple[float | None, float | None]] = {
    "acos": (0.0, math.pi),
    "asin": (-math.pi / 2.0, math.pi / 2.0),
    "atan": (-math.pi / 2.0, math.pi / 2.0),
    "atan2": (-math.pi, math.pi),
    "cosh": (1.0, None),
    "erf": (-1.0, 1.0),
    "erfc": (0.0, 2.0),
    "exp2": (0.0, None),
    "hypot": (0.0, None),
    "tanh": (-1.0, 1.0),
    "ulp": (0.0, None),
}

EXTENDED_MATH_FUNCTIONS = (
    "acos",
    "acosh",
    "asin",
    "asinh",
    "atan",
    "atan2",
    "atanh",
    "cbrt",
    "comb",
    "cosh",
    "dist",
    "erf",
    "erfc",
    "exp2",
    "expm1",
    "fma",
    "fmod",
    "frexp",
    "fsum",
    "gamma",
    "hypot",
    "isqrt",
    "lcm",
    "ldexp",
    "lgamma",
    "log10",
    "log1p",
    "log2",
    "modf",
    "nextafter",
    "perm",
    "pow",
    "prod",
    "remainder",
    "sinh",
    "sumprod",
    "tanh",
    "ulp",
)


def _result_kind(operation: str) -> ResultKind:
    if operation in _INT_RESULTS:
        return "int"
    if operation in _NUMERIC_RESULTS:
        return "numeric"
    if operation in _FLOAT_PAIR_RESULTS:
        return "float_pair"
    return "float"


def _binding_failure(
    function: Callable[..., object],
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    source: str,
) -> ModelResult | None:
    try:
        signature = inspect.signature(function)
    except (TypeError, ValueError):
        return None
    try:
        signature.bind(*args, **kwargs)
    except TypeError as exc:
        return raised_exception(source, exc)
    return None


def _unknown(operation: str) -> ModelDegradation:
    return ModelDegradation(
        kind="unknown",
        label=f"math.{operation}",
        owner="extended math models",
        reason="result and exceptional domain depend on symbolic numeric input",
    )


class ExtendedMathModel(FunctionModel):
    """Use CPython exactly for concrete calls and retain result type otherwise."""

    aliases: tuple[str, ...] = ()

    def __init__(self, operation: str) -> None:
        self._operation = operation
        self._kind = _result_kind(operation)
        self.name = operation
        self.qualname = f"math.{operation}"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        function = cast("Callable[..., object]", getattr(math, self._operation))
        invalid = _binding_failure(function, args, kwargs, self.qualname)
        if invalid is not None:
            return invalid

        resolved_args = [cast("StackValue", SymbolicObject.resolve(arg, state)) for arg in args]
        resolved_kwargs = {
            name: cast("StackValue", SymbolicObject.resolve(value, state))
            for name, value in kwargs.items()
        }
        concrete = concrete_call(resolved_args, resolved_kwargs)
        if concrete is not None:
            try:
                return ModelResult(value=stack_value(function(*concrete[0], **concrete[1])))
            except (TypeError, ValueError, OverflowError) as exc:
                return raised_exception(self.qualname, exc)

        return self._symbolic_result(state)

    def _symbolic_result(self, state: VMState) -> ModelResult:
        degradation = [_unknown(self._operation)]
        if self._kind == "int":
            value, constraint = SymbolicValue.symbolic_int(f"math_{self._operation}_{state.pc}")
            return ModelResult(
                value=value,
                constraints=[constraint, value.z3_int >= 0],
                degradations=degradation,
            )
        if self._kind == "float_pair":
            first, first_constraint = SymbolicValue.symbolic_float(
                f"math_{self._operation}_0_{state.pc}",
            )
            second, second_constraint = SymbolicValue.symbolic_float(
                f"math_{self._operation}_1_{state.pc}",
            )
            return ModelResult(
                value=(first, second),
                constraints=[first_constraint, second_constraint],
                degradations=degradation,
            )
        if self._kind == "numeric":
            value, constraint = SymbolicValue.symbolic_int(f"math_{self._operation}_{state.pc}")
            return ModelResult(
                value=value,
                constraints=[constraint, z3.Or(value.is_float)],
                degradations=degradation,
            )

        value, constraint = SymbolicValue.symbolic_float(f"math_{self._operation}_{state.pc}")
        constraints: list[z3.BoolRef] = [constraint]
        lower, upper = _FLOAT_BOUNDS.get(self._operation, (None, None))
        if lower is not None:
            constraints.append(z3.fpGEQ(value.z3_float, z3.FPVal(lower, z3.Float64())))
        if upper is not None:
            constraints.append(z3.fpLEQ(value.z3_float, z3.FPVal(upper, z3.Float64())))
        return ModelResult(value=value, constraints=constraints, degradations=degradation)


extended_math_models: list[FunctionModel] = [
    ExtendedMathModel(operation) for operation in EXTENDED_MATH_FUNCTIONS
]
