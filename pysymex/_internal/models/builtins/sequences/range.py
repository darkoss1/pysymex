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

"""range() builtin model."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

import z3

from pysymex._internal.models.contracts.results import SideEffects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

from pysymex._internal.core.constants import Z3_ZERO
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

_EAGER_RANGE_MATERIALIZATION_THRESHOLD = 100


class RangeModel(FunctionModel):
    """Model for range()."""

    name = "range"
    qualname = "builtins.range"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply range() model."""
        if len(args) not in {1, 2, 3} or kwargs:
            result, constraint = SymbolicList.symbolic(f"range_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.range",
                    f"range() received invalid positional argument count: {len(args)}",
                ),
            )

        def _const_int(value: StackValue) -> int | None:
            if isinstance(value, int):
                return value
            if isinstance(value, SymbolicValue) and isinstance(value.value, int):
                return value.value
            return None

        def _definite_non_integer_arg(value: StackValue) -> bool:
            if value is None or isinstance(
                value,
                (
                    float,
                    str,
                    bytes,
                    bytearray,
                    SymbolicString,
                    list,
                    tuple,
                    dict,
                    set,
                    frozenset,
                ),
            ):
                return True
            if not isinstance(value, SymbolicValue):
                return False
            if isinstance(value.value, int):
                return False
            if isinstance(
                value.value,
                (float, bytes, bytearray, list, tuple, dict, set, frozenset),
            ):
                return True
            return value.type_tag in {"float", "str", "NoneType"}

        def _concrete_range(range_args: list[StackValue]) -> range | None:
            concrete_values = [_const_int(arg) for arg in range_args]
            if any(value is None for value in concrete_values):
                return None

            values = [value for value in concrete_values if value is not None]
            if len(values) == 1:
                return range(values[0])
            if len(values) == 2:
                return range(values[0], values[1])
            if len(values) >= 3:
                return range(values[0], values[1], values[2])
            return None

        if any(_definite_non_integer_arg(arg) for arg in args):
            result, constraint = SymbolicList.symbolic(f"range_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.range",
                    "range() arguments must be integers",
                ),
            )
        if len(args) == 3 and _const_int(args[2]) == 0:
            result, constraint = SymbolicList.symbolic(f"range_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.value_error(
                    "builtins.range",
                    "range() arg 3 must not be zero",
                ),
            )

        concrete_range = _concrete_range(args)
        if (
            concrete_range is not None
            and len(concrete_range) <= _EAGER_RANGE_MATERIALIZATION_THRESHOLD
        ):
            return ModelResult(
                value=dataclasses.replace(
                    SymbolicList.from_const(list(concrete_range)),
                    _type="range",
                ),
            )

        result, constraint = SymbolicList.symbolic(f"range_{state.pc}")
        result = dataclasses.replace(result, _type="range")
        constraints = [constraint, result.z3_len >= 0]
        if len(args) == 1 and isinstance(args[0], SymbolicValue):
            stop = args[0]
            constraints.append(result.z3_len == z3.If(stop.z3_int > 0, stop.z3_int, Z3_ZERO))
            result.range_start = Z3_ZERO
            result.range_step = ConstraintValues.int(1)
        elif len(args) >= 2:
            start = (
                args[0] if isinstance(args[0], SymbolicValue) else SymbolicValue.from_const(args[0])
            )
            stop = (
                args[1] if isinstance(args[1], SymbolicValue) else SymbolicValue.from_const(args[1])
            )
            if len(args) >= 3:
                step = (
                    args[2]
                    if isinstance(args[2], SymbolicValue)
                    else SymbolicValue.from_const(args[2])
                )
                forward = step.z3_int > 0
                backward = step.z3_int < 0
                distance = z3.If(forward, stop.z3_int - start.z3_int, start.z3_int - stop.z3_int)
                abs_step = z3.If(step.z3_int > 0, step.z3_int, -step.z3_int)
                has_items = z3.Or(
                    z3.And(forward, stop.z3_int > start.z3_int),
                    z3.And(backward, start.z3_int > stop.z3_int),
                )
                length = z3.If(
                    z3.Or(abs_step == 0, z3.Not(has_items)),
                    Z3_ZERO,
                    (distance + abs_step - 1) / abs_step,
                )
                constraints.append(result.z3_len == z3.If(length > 0, length, Z3_ZERO))
                result.range_start = start.z3_int
                result.range_step = step.z3_int
            else:
                length = z3.If(stop.z3_int > start.z3_int, stop.z3_int - start.z3_int, Z3_ZERO)
                constraints.append(result.z3_len == length)
                result.range_start = start.z3_int
                result.range_step = ConstraintValues.int(1)
        if len(args) == 1 and isinstance(args[0], SymbolicValue):
            stop = args[0]
            length = z3.If(stop.z3_int > 0, stop.z3_int, Z3_ZERO)
            constraints.append(result.z3_len == length)
        elif len(args) == 1:
            stop_val = _const_int(args[0])
            if stop_val is not None:
                concrete_length = len(range(stop_val))
                constraints.append(result.z3_len == ConstraintValues.int(concrete_length))
                result.range_start = Z3_ZERO
                result.range_step = ConstraintValues.int(1)
        return ModelResult(value=result, constraints=constraints)
