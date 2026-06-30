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

"""Typed exact-concrete models for common :mod:`statistics` functions."""

from __future__ import annotations

import inspect
import statistics
from typing import TYPE_CHECKING, Literal, cast

from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelDegradation, ModelResult
from pysymex._internal.models.stdlib.literals import concrete_call, raised_exception, stack_value

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

ResultKind = Literal["float", "scalar", "list", "float_pair"]

EXTENDED_STATISTICS_FUNCTIONS = (
    "correlation",
    "covariance",
    "fmean",
    "geometric_mean",
    "harmonic_mean",
    "linear_regression",
    "median_grouped",
    "median_high",
    "median_low",
    "mode",
    "multimode",
    "pstdev",
    "pvariance",
    "quantiles",
    "stdev",
    "variance",
)

_SCALAR_RESULTS = {"median_high", "median_low", "mode"}
_LIST_RESULTS = {"multimode", "quantiles"}
_FLOAT_PAIR_RESULTS = {"linear_regression"}


def _kind(operation: str) -> ResultKind:
    if operation in _SCALAR_RESULTS:
        return "scalar"
    if operation in _LIST_RESULTS:
        return "list"
    if operation in _FLOAT_PAIR_RESULTS:
        return "float_pair"
    return "float"


def _unknown(operation: str) -> ModelDegradation:
    return ModelDegradation(
        kind="unknown",
        label=f"statistics.{operation}",
        owner="statistics models",
        reason="result and sample-size errors depend on symbolic observations",
    )


class StatisticsModel(FunctionModel):
    """Execute concrete statistics calls exactly and retain symbolic result shape."""

    aliases: tuple[str, ...] = ()

    def __init__(self, operation: str) -> None:
        self._operation = operation
        self._kind = _kind(operation)
        self.name = operation
        self.qualname = f"statistics.{operation}"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        function = cast("Callable[..., object]", getattr(statistics, self._operation))
        invalid = self._binding_failure(function, args, kwargs)
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
            except (statistics.StatisticsError, TypeError, ValueError, ZeroDivisionError) as exc:
                return raised_exception(self.qualname, exc)
        return self._symbolic_result(state)

    def _binding_failure(
        self,
        function: Callable[..., object],
        args: list[StackValue],
        kwargs: dict[str, StackValue],
    ) -> ModelResult | None:
        try:
            inspect.signature(function).bind(*args, **kwargs)
        except TypeError as exc:
            return raised_exception(self.qualname, exc)
        return None

    def _symbolic_result(self, state: VMState) -> ModelResult:
        degradations = [_unknown(self._operation)]
        if self._kind == "float":
            value, constraint = SymbolicValue.symbolic_float(
                f"statistics_{self._operation}_{state.pc}",
            )
            return ModelResult(value=value, constraints=[constraint], degradations=degradations)
        if self._kind == "list":
            value, constraint = SymbolicList.symbolic(f"statistics_{self._operation}_{state.pc}")
            return ModelResult(value=value, constraints=[constraint], degradations=degradations)
        if self._kind == "float_pair":
            first, first_constraint = SymbolicValue.symbolic_float(
                f"statistics_{self._operation}_0_{state.pc}",
            )
            second, second_constraint = SymbolicValue.symbolic_float(
                f"statistics_{self._operation}_1_{state.pc}",
            )
            return ModelResult(
                value=(first, second),
                constraints=[first_constraint, second_constraint],
                degradations=degradations,
            )
        value, constraint = SymbolicValue.symbolic(f"statistics_{self._operation}_{state.pc}")
        return ModelResult(value=value, constraints=[constraint], degradations=degradations)


extended_statistics_models: list[FunctionModel] = [
    StatisticsModel(operation) for operation in EXTENDED_STATISTICS_FUNCTIONS
]
