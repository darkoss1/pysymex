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

"""Finite-iterator loop-bound adjustments."""

from __future__ import annotations

import dis
from collections.abc import Iterable, Iterator, Sized
from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.containers.generators import ModeledGenerator
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.scheduling.loop.bounds.context import LoopBoundContext


def effective_max_loop_iterations(context: LoopBoundContext, state: VMState) -> int | None:
    """Return an explicit loop override extended for exact finite iterators."""
    configured_limit = context.max_loop_iterations
    if configured_limit is None:
        return None
    finite_length = finite_iterator_length(state)
    if finite_length is None or finite_length < 0:
        return configured_limit
    return max(configured_limit, finite_length + 1)


def finite_iterator_length(state: VMState) -> int | None:
    """Return a finite length for the active iterator when one is known cheaply."""
    if not state.stack:
        return None
    iterator = state.stack[-1]
    if isinstance(iterator, ModeledGenerator):
        from pysymex._internal.execution.scheduling.loop.bounds.generators import (
            finite_generator_yield_upper_bound,
        )

        return finite_generator_yield_upper_bound(iterator)
    iterator = _active_symbolic_iterator(state)
    if iterator is None:
        return None
    from pysymex._internal.models.builtins.iteration.sources import IterationSources

    concrete_items = IterationSources.iterator_items(iterator, state)
    if concrete_items is not None:
        return len(concrete_items)
    iterable = iterator.iterable
    if isinstance(iterable, SymbolicList):
        concrete_items = iterable.concrete_items
        if concrete_items is not None:
            return len(concrete_items)
        return exact_int_value(iterable.z3_len, state.path_constraints)
    if isinstance(iterable, SymbolicString):
        return exact_int_value(iterable.z3_len, state.path_constraints)
    if isinstance(iterable, Sized):
        return len(iterable)
    return None


def finite_iterator_upper_bound(state: VMState) -> int | None:
    """Return a proven finite upper bound for the active iterator length."""
    exact_length = finite_iterator_length(state)
    if exact_length is not None:
        return exact_length
    if not state.stack:
        return None
    iterator = _active_symbolic_iterator(state)
    if iterator is None:
        return None
    iterable = iterator.iterable
    if isinstance(iterable, (SymbolicList, SymbolicString)):
        return _integer_expr_upper_bound(iterable.z3_len, state.path_constraints)
    return None


def _active_symbolic_iterator(state: VMState) -> SymbolicIterator | None:
    """Return the iterator operand for ``FOR_ITER`` or generator delegation."""
    if state.stack and isinstance(state.stack[-1], SymbolicIterator):
        return state.stack[-1]
    instructions = state.current_instructions
    if instructions is None or state.pc >= len(instructions):
        return None
    instruction = instructions[state.pc]
    if (
        isinstance(instruction, dis.Instruction)
        and instruction.opname in {"SEND", "YIELD_FROM"}
        and len(state.stack) >= 2
        and isinstance(state.stack[-2], SymbolicIterator)
    ):
        return state.stack[-2]
    return None


def finite_countdown_remaining_steps(previous: VMState, current: VMState) -> int | None:
    """Return a proven finite remainder for a unit-decrement local recurrence.

    The proof is deliberately narrow: a common integer local must retain one
    base symbol, decrease by exactly one, and have a direct finite upper bound
    in the current path constraints. The policy rechecks this proof at every
    header visit instead of converting it into an internal iteration cap.
    """
    for name in set(previous.local_vars) & set(current.local_vars):
        if not isinstance(previous.local_vars[name], SymbolicValue) or not isinstance(
            current.local_vars[name],
            SymbolicValue,
        ):
            continue
        remaining = finite_countdown_value_remaining_steps(
            previous.local_vars[name],
            current.local_vars[name],
            current.path_constraints,
        )
        if remaining is not None:
            return remaining
    return None


def finite_countdown_value_remaining_steps(
    previous: object,
    current: object,
    constraints: Iterable[z3.BoolRef],
) -> int | None:
    """Return a finite remainder for one concrete or bounded symbolic countdown."""
    if isinstance(previous, int) and not isinstance(previous, bool):
        if isinstance(current, int) and not isinstance(current, bool):
            if current == previous - 1 and current >= 0:
                return current
        return None
    if not isinstance(previous, SymbolicValue) or not isinstance(current, SymbolicValue):
        return None
    if not z3.is_true(simplify_expr(previous.is_int)) or not z3.is_true(
        simplify_expr(current.is_int),
    ):
        return None

    old_affine = _unit_affine_int(previous.z3_int)
    new_affine = _unit_affine_int(current.z3_int)
    if old_affine is None or new_affine is None:
        return None
    old_base, old_offset = old_affine
    new_base, new_offset = new_affine
    if not z3.eq(old_base, new_base) or new_offset != old_offset - 1:
        return None

    base_upper = _direct_integer_upper_bound(new_base, constraints)
    if base_upper is None:
        return None
    return max(0, base_upper + new_offset)


def _unit_affine_int(expr: z3.ArithRef) -> tuple[z3.ExprRef, int] | None:
    """Decompose ``symbol + constant`` integer expressions."""
    simplified = simplify_expr(expr)
    if _is_uninterpreted_int_constant(simplified):
        return simplified, 0

    terms = simplified.children() if z3.is_add(simplified) else (simplified,)
    base: z3.ExprRef | None = None
    offset = 0
    for term in terms:
        term = simplify_expr(term)
        if z3.is_int_value(term):
            offset += term.as_long()
            continue
        if not _is_uninterpreted_int_constant(term) or base is not None:
            return None
        base = term
    if base is None:
        return None
    return base, offset


def _is_uninterpreted_int_constant(expr: z3.ExprRef) -> bool:
    """Return whether *expr* is one integer symbol rather than an application."""
    return (
        z3.is_const(expr)
        and expr.sort().kind() == z3.Z3_INT_SORT
        and expr.decl().kind() == z3.Z3_OP_UNINTERPRETED
    )


def _direct_integer_upper_bound(
    base: z3.ExprRef,
    constraints: Iterable[z3.BoolRef],
) -> int | None:
    """Return the tightest direct integer upper bound for one base symbol."""
    bounds: list[int] = []
    for constraint in iter_conjuncts(constraints):
        simplified = simplify_expr(constraint)
        if z3.is_eq(simplified):
            left, right = simplified.children()
            bound = _upper_bound_from_relation(base, left, right, strict=False)
            if bound is None:
                bound = _upper_bound_from_relation(base, right, left, strict=False)
        elif z3.is_le(simplified) or z3.is_lt(simplified):
            left, right = simplified.children()
            bound = _upper_bound_from_relation(
                base,
                left,
                right,
                strict=z3.is_lt(simplified),
            )
        elif z3.is_ge(simplified) or z3.is_gt(simplified):
            left, right = simplified.children()
            bound = _upper_bound_from_relation(
                base,
                right,
                left,
                strict=z3.is_gt(simplified),
            )
        else:
            continue
        if bound is not None:
            bounds.append(bound)
    return min(bounds) if bounds else None


def _integer_expr_upper_bound(
    expr: z3.ArithRef,
    constraints: Iterable[z3.BoolRef],
    *,
    _visited: frozenset[int] = frozenset(),
) -> int | None:
    """Propagate a finite upper bound through simple integer expressions."""
    simplified = simplify_expr(expr)
    if z3.is_int_value(simplified):
        return simplified.as_long()
    if simplified.hash() in _visited:
        return None
    visited = _visited | {simplified.hash()}

    affine = _unit_affine_int(simplified)
    if affine is not None:
        base, offset = affine
        direct = _direct_integer_upper_bound(base, constraints)
        if direct is not None:
            return direct + offset

    if z3.is_app_of(simplified, z3.Z3_OP_ITE):
        _condition, when_true, when_false = simplified.children()
        true_bound = _integer_expr_upper_bound(
            cast("z3.ArithRef", when_true),
            constraints,
            _visited=visited,
        )
        false_bound = _integer_expr_upper_bound(
            cast("z3.ArithRef", when_false),
            constraints,
            _visited=visited,
        )
        if true_bound is not None and false_bound is not None:
            return max(true_bound, false_bound)

    for constraint in iter_conjuncts(constraints):
        equality = simplify_expr(constraint)
        if not z3.is_eq(equality):
            continue
        left, right = equality.children()
        if z3.eq(simplified, left):
            bound = _integer_expr_upper_bound(
                cast("z3.ArithRef", right),
                constraints,
                _visited=visited,
            )
        elif z3.eq(simplified, right):
            bound = _integer_expr_upper_bound(
                cast("z3.ArithRef", left),
                constraints,
                _visited=visited,
            )
        else:
            continue
        if bound is not None:
            return bound
    return None


def _upper_bound_from_relation(
    base: z3.ExprRef,
    left: z3.ExprRef,
    right: z3.ExprRef,
    *,
    strict: bool,
) -> int | None:
    """Extract ``base + offset <= constant`` from one normalized relation."""
    affine = _unit_affine_int(cast("z3.ArithRef", left))
    right = simplify_expr(right)
    if affine is None or not z3.is_int_value(right):
        return None
    relation_base, offset = affine
    if not z3.eq(base, relation_base):
        return None
    return right.as_long() - offset - int(strict)


def exact_int_value(expr: z3.ArithRef, constraints: Iterable[z3.BoolRef]) -> int | None:
    """Return a concrete integer value implied by direct equality constraints."""
    simplified = simplify_expr(expr)
    if z3.is_int_value(simplified):
        return simplified.as_long()

    known: dict[int, int] = {}
    aliases: list[tuple[z3.ExprRef, z3.ExprRef]] = []
    for constraint in iter_conjuncts(constraints):
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


def iter_conjuncts(constraints: Iterable[z3.BoolRef]) -> Iterator[z3.BoolRef]:
    """Yield top-level conjuncts from path constraints."""
    pending: list[z3.BoolRef] = list(constraints)
    while pending:
        constraint = pending.pop()
        if z3.is_and(constraint):
            pending.extend(cast("list[z3.BoolRef]", constraint.children()))
            continue
        yield constraint
