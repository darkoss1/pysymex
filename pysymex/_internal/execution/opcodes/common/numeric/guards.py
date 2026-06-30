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

"""Numeric feasibility guards for exceptional arithmetic paths."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.constants import Z3_ZERO
from pysymex._internal.core.solver.constraints.arithmetic import tagged_numeric_zero_condition
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.opcodes.common.satisfiability import PathSatisfiability

if TYPE_CHECKING:
    import z3

    from pysymex._internal.core.state.record import VMState


def division_by_zero_possible(
    right: object,
    state: VMState,
    op: str,
    left: object,
) -> bool:
    """Return whether the current path allows a division-like zero divisor."""
    _ = (op, left)
    if isinstance(right, SymbolicValue):
        return PathSatisfiability.is_sat(
            [*state.path_constraints.to_list(), right.z3_int == Z3_ZERO],
        )
    return isinstance(right, (int, float, bool)) and right == 0


def check_negative_shift(
    right: object,
    state: VMState,
    op: str,
    left: object,
) -> bool:
    """Return whether the current path allows a negative shift count."""
    _ = (op, left)
    if isinstance(right, SymbolicValue):
        return PathSatisfiability.is_sat(
            [*state.path_constraints.to_list(), right.z3_int < Z3_ZERO],
        )
    return isinstance(right, int) and right < 0


def division_by_zero_condition(right: SymbolicValue, is_truediv: bool = False) -> z3.BoolRef:
    """Build the zero-divisor condition used by division-like opcodes."""
    return tagged_numeric_zero_condition(
        concrete_value=right.value,
        affinity_type=right.affinity_type,
        is_int=right.is_int,
        int_expr=right.z3_int,
        is_bool=right.is_bool,
        bool_expr=right.z3_bool,
        is_float=right.is_float,
        float_expr=right.z3_float,
        include_float=not is_truediv,
    )
