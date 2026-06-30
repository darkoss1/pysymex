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

"""Symbolic sequence ``FOR_ITER`` branch handling."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.state.record import StateConstraints
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.control.feasibility.branching import branch_feasible
from pysymex._internal.execution.opcodes.common.control.iteration.exit import (
    push_for_iter_exit_sentinel,
)
from pysymex._internal.execution.opcodes.common.control.iteration.state import (
    state_with_iterator_update,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.types.containers.lists import SymbolicList
    from pysymex._internal.core.types.scalars.strings import SymbolicString
    from pysymex._internal.typing.protocols import StackValue


def iter_symbolic_string(
    *,
    state: VMState,
    iterator: StackValue,
    iterable: SymbolicString,
    idx: int,
    target_index: int,
    push_exit_sentinel: bool = True,
    pop_exit_iterator: bool = False,
) -> OpcodeResult:
    """Iterate a symbolic string with length-bound branch constraints."""
    idx_expr = ConstraintValues.int(idx)
    continue_condition = idx_expr < iterable.z3_len
    exit_condition = idx_expr >= iterable.z3_len
    exact_length = _exact_int_value(iterable.z3_len, state.path_constraints)
    branches: list[VMState] = []
    known_prefix_len = StateConstraints.known_sat_prefix_len(state)

    if (exact_length is not None and idx < exact_length) or (
        exact_length is None
        and branch_feasible(
            state.path_constraints,
            continue_condition,
            known_sat_prefix_len=known_prefix_len,
        )
    ):
        continue_state = state.fork()
        if isinstance(iterator, SymbolicIterator):
            updated_iterator = iterator.advance()
            continue_state = state_with_iterator_update(
                continue_state,
                iterator,
                updated_iterator,
            )
            continue_state.pop()
            continue_state = continue_state.push(updated_iterator)
        continue_state = continue_state.push(iterable.substring(idx, idx + 1))
        continue_state = continue_state.add_constraint(continue_condition)
        branches.append(continue_state.advance_pc())

    if (exact_length is not None and idx >= exact_length) or (
        exact_length is None
        and branch_feasible(
            state.path_constraints,
            exit_condition,
            known_sat_prefix_len=known_prefix_len,
        )
    ):
        exit_state = state.fork()
        if isinstance(iterator, SymbolicIterator):
            exit_state = state_with_iterator_update(
                exit_state,
                iterator,
                iterator.exhaust(),
            )
        exit_state = exit_state.add_constraint(exit_condition)
        exit_state = push_for_iter_exit_sentinel(
            exit_state,
            push_sentinel=push_exit_sentinel,
            pop_iterator=pop_exit_iterator,
        )
        branches.append(exit_state.set_pc(target_index))

    if not branches:
        return OpcodeResult.terminate()
    return OpcodeResult.branch(branches)


def iter_symbolic_list(
    state: VMState,
    iterator: StackValue,
    iterable: SymbolicList,
    *,
    target_index: int,
    push_exit_sentinel: bool = True,
    pop_exit_iterator: bool = False,
) -> OpcodeResult:
    """Iterate a symbolic list with length and element-value constraints."""
    continue_state = state.fork()

    if isinstance(iterator, SymbolicIterator):
        updated_iterator = iterator.advance()
        continue_state = state_with_iterator_update(
            continue_state,
            iterator,
            updated_iterator,
        )
        continue_state.pop()
        continue_state = continue_state.push(updated_iterator)

    iter_val, type_constraint = SymbolicValue.symbolic(f"iter_{state.pc}_{state.path_id}")
    continue_state = continue_state.push(iter_val)
    continue_state = continue_state.add_constraint(type_constraint)

    exit_state = state.fork()
    if isinstance(iterator, SymbolicIterator):
        exit_state = state_with_iterator_update(
            exit_state,
            iterator,
            iterator.exhaust(),
        )
    exit_state = exit_state.set_pc(target_index)

    z3_len = iterable.z3_len
    idx = iterator.index if isinstance(iterator, SymbolicIterator) else 0

    idx_expr = ConstraintValues.int(idx)
    continue_condition = idx_expr < z3_len
    exit_condition = idx_expr >= z3_len
    branches: list[VMState] = []
    known_prefix_len = StateConstraints.known_sat_prefix_len(state)

    if branch_feasible(
        state.path_constraints,
        continue_condition,
        known_sat_prefix_len=known_prefix_len,
    ):
        continue_state = continue_state.add_constraint(continue_condition)
        continue_state = continue_state.add_constraint(
            iter_val.z3_int == iterable.element_expr_at(idx_expr),
        )

        if iterable.element_type == "int":
            continue_state = continue_state.add_constraint(iter_val.is_int == Z3_TRUE)
            continue_state = continue_state.add_constraint(iter_val.is_bool == Z3_FALSE)
            continue_state = continue_state.add_constraint(iter_val.is_float == Z3_FALSE)
            continue_state = continue_state.add_constraint(iter_val.is_str == Z3_FALSE)
            continue_state = continue_state.add_constraint(iter_val.is_obj == Z3_FALSE)
            continue_state = continue_state.add_constraint(iter_val.is_none == Z3_FALSE)
        branches.append(continue_state.advance_pc())

    if branch_feasible(
        state.path_constraints,
        exit_condition,
        known_sat_prefix_len=known_prefix_len,
    ):
        exit_state = exit_state.add_constraint(exit_condition)
        exit_state = push_for_iter_exit_sentinel(
            exit_state,
            push_sentinel=push_exit_sentinel,
            pop_iterator=pop_exit_iterator,
        )
        branches.append(exit_state)

    if not branches:
        return OpcodeResult.terminate()
    return OpcodeResult.branch(branches)


def _exact_int_value(expr: z3.ArithRef, constraints: Iterable[z3.BoolRef]) -> int | None:
    """Return a concrete integer value implied by direct equality constraints."""
    simplified = simplify_expr(expr)
    if z3.is_int_value(simplified):
        return simplified.as_long()

    known: dict[int, int] = {}
    aliases: list[tuple[z3.ExprRef, z3.ExprRef]] = []
    for constraint in _iter_conjuncts(constraints):
        constraint = simplify_expr(constraint)
        if not z3.is_eq(constraint):
            continue
        left, right = constraint.children()
        left_simplified = simplify_expr(left)
        right_simplified = simplify_expr(right)
        if z3.is_int_value(left_simplified):
            known[right.hash()] = left_simplified.as_long()
        elif z3.is_int_value(right_simplified):
            known[left.hash()] = right_simplified.as_long()
        else:
            aliases.append((left, right))

    for _ in range(len(aliases) + 1):
        changed = False
        for left, right in aliases:
            left_hash = left.hash()
            right_hash = right.hash()
            if left_hash in known and right_hash not in known:
                known[right_hash] = known[left_hash]
                changed = True
            elif right_hash in known and left_hash not in known:
                known[left_hash] = known[right_hash]
                changed = True
        if not changed:
            break
    return known.get(expr.hash())


def _iter_conjuncts(constraints: Iterable[z3.BoolRef]) -> Iterator[z3.BoolRef]:
    """Yield top-level conjuncts from path constraints."""
    pending: list[z3.BoolRef] = list(constraints)
    while pending:
        constraint = pending.pop()
        if z3.is_and(constraint):
            pending.extend(cast("list[z3.BoolRef]", constraint.children()))
            continue
        yield constraint
