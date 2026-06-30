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

"""Precise concrete-backed list item selection for ``BINARY_SUBSCR`` reads."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.solver.constraints.literals import exact_bool_literal
from pysymex._internal.core.state.record import StateConstraints
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.opcodes.common.lowering.subscripts import to_stack_value
from pysymex._internal.execution.opcodes.common.lowering.types import LoweredValue
from pysymex._internal.core.types.containers.sequence_precision import (
    concrete_sequence_index,
    exact_index_from_constraints,
    normalize_concrete_index,
    normalized_index_alias,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.core.solver.engine.results import SolverResult
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def single_feasible_concrete_list_item(
    container: object,
    index: StackValue,
    state: VMState,
    *,
    path_is_sat_fn: Callable[..., bool],
    check_sat_result_fn: Callable[..., SolverResult],
    get_model_fn: Callable[..., z3.ModelRef | None],
) -> LoweredValue | None:
    """Return a lowered item when exactly one concrete list index is feasible."""
    if not isinstance(index, SymbolicValue):
        return None
    concrete_items = _retained_sequence_items(container)
    if not concrete_items:
        return None

    concrete_index = concrete_sequence_index(index, len(concrete_items))
    if concrete_index is not None:
        try:
            return LoweredValue(to_stack_value(concrete_items[concrete_index]))
        except IndexError:
            return None

    constraints = state.path_constraints.to_list()
    known_prefix_len = StateConstraints.known_sat_prefix_len(state)
    idx = index.z3_int
    length = len(concrete_items)
    item_index = exact_index_from_constraints(idx, length, constraints)
    if item_index is not None:
        if check_sat_result_fn(constraints, known_sat_prefix_len=known_prefix_len).is_sat:
            return LoweredValue(to_stack_value(concrete_items[item_index]))
        return None

    out_of_bounds = z3.Or(idx < -length, idx >= length)
    out_of_bounds_literal = exact_bool_literal(out_of_bounds)
    if out_of_bounds_literal is True or (
        out_of_bounds_literal is None
        and path_is_sat_fn([*constraints, out_of_bounds], known_sat_prefix_len=known_prefix_len)
    ):
        return None

    if length == 1:
        return LoweredValue(to_stack_value(concrete_items[0]))

    string_selection = _finite_string_selection(container, concrete_items, index, length)
    if string_selection is not None:
        return LoweredValue(string_selection)

    in_bounds_constraints = [*constraints, idx >= -length, idx < length]
    if item_index is None:
        if _concrete_items_have_precise_integer_channel(concrete_items):
            return None
        model = get_model_fn(in_bounds_constraints)
        if model is None:
            return None

        modeled_index = _model_int(model, idx)
        if modeled_index is None:
            return None

        item_index = normalize_concrete_index(modeled_index, length)
        if item_index is None:
            return None

    other_item_possible = z3.And(
        idx >= -length,
        idx < length,
        z3.Not(normalized_index_alias(idx, item_index, length)),
    )
    other_item_literal = exact_bool_literal(other_item_possible)
    if other_item_literal is True or (
        other_item_literal is None
        and path_is_sat_fn(
            [*constraints, other_item_possible],
            known_sat_prefix_len=known_prefix_len,
        )
    ):
        return None

    return LoweredValue(to_stack_value(concrete_items[item_index]))


def _retained_sequence_items(container: object) -> list[object] | None:
    """Return exact retained items for sequence containers handled by this fast path."""
    if isinstance(container, SymbolicList):
        return container.concrete_items
    if isinstance(container, list):
        return list(cast("list[object]", container))
    if isinstance(container, tuple):
        return list(cast("tuple[object, ...]", container))
    return None


def _finite_string_selection(
    container: object,
    concrete_items: list[object],
    index: SymbolicValue,
    length: int,
) -> SymbolicString | None:
    """Return exact finite-domain string selection for an in-bounds symbolic index."""
    selected_str: z3.SeqRef | None = None
    selected_len: z3.ArithRef | None = None
    for position, item in reversed(tuple(enumerate(concrete_items))):
        item_str, item_len = _string_item_channels(item)
        if item_str is None or item_len is None:
            return None
        if selected_str is None or selected_len is None:
            selected_str = item_str
            selected_len = item_len
            continue
        condition = normalized_index_alias(index.z3_int, position, length)
        selected_str = z3.If(condition, item_str, selected_str)
        selected_len = z3.If(condition, item_len, selected_len)

    if selected_str is None or selected_len is None:
        return None
    return SymbolicString(
        _z3_str=simplify_expr(selected_str),
        _z3_len=simplify_expr(selected_len),
        _name=f"{_container_name(container)}[{index.name}]",
    )


def _string_item_channels(item: object) -> tuple[z3.SeqRef | None, z3.ArithRef | None]:
    """Return Z3 string and length channels for definite retained string items."""
    if isinstance(item, str):
        return ConstraintValues.string(item), ConstraintValues.int(len(item))
    if isinstance(item, SymbolicString):
        return item.z3_str, item.z3_len
    if isinstance(item, SymbolicValue) and z3.is_true(simplify_expr(item.is_str)):
        return item.z3_str, z3.Length(item.z3_str)
    return None, None


def _container_name(container: object) -> str:
    name = getattr(container, "name", None)
    if isinstance(name, str) and name:
        return name
    if isinstance(container, tuple):
        return "tuple"
    if isinstance(container, list):
        return "list"
    return "sequence"


def _concrete_items_have_precise_integer_channel(concrete_items: list[object]) -> bool:
    """Return whether symbolic array fallback preserves all retained item payloads."""
    for item in concrete_items:
        if isinstance(item, bool | int):
            continue
        if isinstance(item, SymbolicValue) and item.affinity_type in {"int", "bool"}:
            continue
        return False
    return True


def _model_int(model: z3.ModelRef, expr: z3.ArithRef) -> int | None:
    """Extract an integer witness from a model without treating failure as proof."""
    try:
        value = model.eval(expr, model_completion=True)
    except z3.Z3Exception:
        return None
    if not z3.is_int_value(value):
        return None
    return value.as_long()
