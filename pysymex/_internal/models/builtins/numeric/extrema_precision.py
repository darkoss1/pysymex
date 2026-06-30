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

"""Precision helpers for min()/max() over definite symbolic integer operands."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal, cast

import z3

from pysymex._internal.models.builtins.iteration.consumption import (
    iterator_exhaustion_side_effect as _iterator_exhaustion_side_effect,
)
from pysymex._internal.models.builtins.iteration.sources import IterationSources
from pysymex._internal.models.builtins.numeric.sum_precision import (
    contains_symbolic_operand,
    int_operand_expr,
)
from pysymex._internal.models.contracts.results import ModelResult, SideEffectValue

if TYPE_CHECKING:
    from collections.abc import Sequence

    from pysymex._internal.core.state.record import VMState


def concrete_sequence_items(value: object, state: VMState) -> list[object] | None:
    """Return retained items for concrete or concrete-backed finite iterables."""
    concrete_items = IterationSources.iterable_items(value, state)
    return list(concrete_items) if concrete_items is not None else None


def iterator_exhaustion_side_effect(
    value: object,
    state: VMState,
) -> dict[str, SideEffectValue] | None:
    """Return an iterator mutation side effect for reducers that consume to exhaustion."""
    return cast(
        "dict[str, SideEffectValue] | None",
        _iterator_exhaustion_side_effect(value, state),
    )


def model_result_with_side_effects(
    result: ModelResult,
    side_effects: dict[str, SideEffectValue] | None,
) -> ModelResult:
    """Return ``result`` plus additional side effects, preserving constraints."""
    if not side_effects:
        return result
    merged = dict(result.side_effects)
    merged.update(side_effects)
    return ModelResult(value=result.value, constraints=result.constraints, side_effects=merged)


def symbolic_extreme_result(
    values: Sequence[object],
    name: str,
    kind: Literal["min", "max"],
) -> ModelResult | None:
    """Return a constrained symbolic int for supported ``min``/``max`` operands."""
    if not values or not contains_symbolic_operand(values, 0):
        return None

    first = int_operand_expr(values[0])
    if first is None:
        return None
    expression = first
    for value in values[1:]:
        candidate = int_operand_expr(value)
        if candidate is None:
            return None
        if kind == "min":
            expression = z3.If(candidate < expression, candidate, expression)
        else:
            expression = z3.If(candidate > expression, candidate, expression)

    result, constraints = ModelResult.symbolic_int(name)
    constraints.append(result.z3_int == expression)
    return ModelResult(value=result, constraints=constraints)
