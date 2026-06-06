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

from typing import TYPE_CHECKING

import z3

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

from pysymex.config.defaults import DEFAULT_LIMIT_MAX_LIST_LENGTH
from pysymex.core.constants import Z3_ZERO
from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue

from ..base import FunctionModel, ModelResult
from .helpers import type_error_side_effect, value_error_side_effect


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
                side_effects=type_error_side_effect(
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
                (float, str, bytes, bytearray, SymbolicString, list, tuple, dict, set),
            ):
                return True
            if not isinstance(value, SymbolicValue):
                return False
            if isinstance(value.value, int):
                return False
            if isinstance(value.value, (float, bytes, bytearray, list, tuple, dict, set)):
                return True
            return value.type_tag in {"float", "str", "NoneType"}

        def _bounded_range_entries(
            range_args: list[StackValue],
        ) -> tuple[int, tuple[int, ...]] | None:
            concrete_values = [_const_int(arg) for arg in range_args]
            if any(value is None for value in concrete_values):
                return None

            values = [value for value in concrete_values if value is not None]
            if len(values) == 1:
                seq = tuple(range(values[0]))
            elif len(values) == 2:
                seq = tuple(range(values[0], values[1]))
            elif len(values) >= 3:
                seq = tuple(range(values[0], values[1], values[2]))
            else:
                return None
            return len(seq), seq

        if any(_definite_non_integer_arg(arg) for arg in args):
            result, constraint = SymbolicList.symbolic(f"range_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.range", "range() arguments must be integers"
                ),
            )
        if len(args) == 3 and _const_int(args[2]) == 0:
            result, constraint = SymbolicList.symbolic(f"range_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=value_error_side_effect(
                    "builtins.range", "range() arg 3 must not be zero"
                ),
            )

        bounded_entries = _bounded_range_entries(args)
        if bounded_entries is not None and bounded_entries[0] <= DEFAULT_LIMIT_MAX_LIST_LENGTH:
            _, entries = bounded_entries
            return ModelResult(value=SymbolicList.from_const(list(entries)))

        result, constraint = SymbolicList.symbolic(f"range_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        if bounded_entries is not None:
            _, entries = bounded_entries
            setattr(result, "_concrete_items", list(entries))

        if len(args) == 1 and isinstance(args[0], SymbolicValue):
            stop = args[0]
            constraints.append(result.z3_len == z3.If(stop.z3_int > 0, stop.z3_int, Z3_ZERO))
            result.range_start = Z3_ZERO
            result.range_step = get_int_val(1)
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
                diff = stop.z3_int - start.z3_int

                abs_diff = z3.If(diff * step.z3_int > 0, diff, Z3_ZERO)
                abs_step = z3.If(step.z3_int > 0, step.z3_int, -step.z3_int)
                length = z3.If(abs_step == 0, Z3_ZERO, (abs_diff + abs_step - 1) / abs_step)
                constraints.append(result.z3_len == z3.If(length > 0, length, Z3_ZERO))
                result.range_start = start.z3_int
                result.range_step = step.z3_int
            else:
                length = z3.If(stop.z3_int > start.z3_int, stop.z3_int - start.z3_int, Z3_ZERO)
                constraints.append(result.z3_len == length)
                result.range_start = start.z3_int
                result.range_step = get_int_val(1)
        if len(args) == 1 and isinstance(args[0], SymbolicValue):
            stop = args[0]
            length = z3.If(stop.z3_int > 0, stop.z3_int, Z3_ZERO)
            constraints.append(result.z3_len == length)
        elif len(args) == 1:
            stop_val = _const_int(args[0])
            if stop_val is not None:
                entries = tuple(range(stop_val))
                constraints.append(result.z3_len == get_int_val(len(entries)))
                result.range_start = Z3_ZERO
                result.range_step = get_int_val(1)
        return ModelResult(value=result, constraints=constraints)
