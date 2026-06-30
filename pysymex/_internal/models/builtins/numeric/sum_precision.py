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

"""Precision helpers for ``sum()`` over definite symbolic integer operands."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.constants import Z3_ONE, Z3_ZERO
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.base import SymbolicType
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from collections.abc import Sequence


def symbolic_sum_result(
    values: Sequence[object],
    start: object,
    name: str,
) -> ModelResult | None:
    """Return a constrained symbolic int result for supported ``sum`` operands.

    Only definite int/bool concrete values and int/bool-affinity symbolic values
    are modeled. Other operands return ``None`` so the caller can use existing
    unsupported/type-error behavior instead of silently approximating.
    """
    if not contains_symbolic_operand(values, start):
        return None

    total = int_operand_expr(start)
    if total is None:
        return None
    for value in values:
        value_expr = int_operand_expr(value)
        if value_expr is None:
            return None
        total = total + value_expr

    result, constraints = ModelResult.symbolic_int(name)
    constraints.append(result.z3_int == total)
    return ModelResult(value=result, constraints=constraints)


def contains_symbolic_operand(values: Sequence[object], start: object) -> bool:
    return isinstance(start, (SymbolicValue, SymbolicType)) or any(
        isinstance(value, (SymbolicValue, SymbolicType)) for value in values
    )


def int_operand_expr(value: object) -> z3.ArithRef | None:
    if isinstance(value, bool):
        return Z3_ONE if value else Z3_ZERO
    if isinstance(value, int):
        return ConstraintValues.int(value)
    if not isinstance(value, SymbolicValue):
        return None
    if value.affinity_type == "bool":
        return z3.If(value.z3_bool, Z3_ONE, Z3_ZERO)
    if value.affinity_type == "int":
        return value.z3_int
    if isinstance(value.value, bool):
        return Z3_ONE if value.value else Z3_ZERO
    if isinstance(value.value, int):
        return ConstraintValues.int(value.value)
    return None
