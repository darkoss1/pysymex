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

"""``GET_ITER``, ``FOR_ITER``, and related iterator opcode handlers.

Builds :class:`~pysymex.core.types.containers.sequences.SymbolicIterator` views over
modeled containers or introduces symbolic iteration state with
``UNSUPPORTED_ITERATION_PROTOCOL`` when ``__iter__`` is not modeled. Re-exported from
:mod:`pysymex.execution.opcodes.common.control.flow`.
"""

from __future__ import annotations

import dis
from collections.abc import Iterable, Iterator, Sequence
from typing import TYPE_CHECKING, cast

import z3

from pysymex.core.types.containers.callable_iterators import CallableSentinelIterator
from pysymex.core.types.containers.sequences import SymbolicIterator
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.base import fresh_name
from pysymex.core.constants import Z3_FALSE
from pysymex.core.constants import Z3_TRUE
from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.feasibility import known_sat_prefix_len_for_state
from pysymex.execution.opcodes.common.control.feasibility import branch_feasible
from pysymex.execution.opcodes.common.control.iteration_items import (
    stack_value_from_concrete_iter_item,
)
from pysymex.execution.opcodes.common.functions.protocol.fallbacks import (
    ITERATION_PROTOCOL_UNAVAILABLE_REASON,
    UNSUPPORTED_ITERATION_PROTOCOL,
    unsupported_iteration_event,
)
from pysymex.execution.opcodes.common.generators import (
    ModeledGenerator,
    resume_generator_for_iter,
)
from pysymex.models.builtins.core.iterator_items import concrete_iterator_items

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def handle_common_for_iter(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Iterate over a sequence with symbolic index tracking."""
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is None:
        target_index = state.pc + 2

    if not state.stack:
        return OpcodeResult.continue_with(state.set_pc(target_index))

    iterator = state.peek()
    if isinstance(iterator, CallableSentinelIterator):
        from pysymex.execution.opcodes.common.control.callable_sentinel_iteration import (
            dispatch_callable_sentinel_iteration,
        )

        callable_result = dispatch_callable_sentinel_iteration(
            state,
            ctx,
            iterator,
            target_index=target_index,
        )
        if callable_result is not None:
            return callable_result
    if isinstance(iterator, SymbolicValue):
        from pysymex.execution.opcodes.common.numeric.helpers import lookup_modeled_method

        next_method = lookup_modeled_method(iterator, "__next__")
        if next_method is not None:
            from pysymex.execution.calls.interprocedural import (
                perform_interprocedural_call_impl,
            )
            from pysymex.execution.opcodes.common.control.sequence_iteration import (
                NEXT_ITER_PROTOCOL,
                next_iteration_retained_operand,
            )

            result = perform_interprocedural_call_impl(
                state,
                ctx,
                next_method,
                [],
                {},
                protocol_method=NEXT_ITER_PROTOCOL,
                protocol_retained_operand=next_iteration_retained_operand(target_index),
            )
            if result is not None:
                return result
            return OpcodeResult(
                new_states=[],
                issues=[],
                degraded_passes=[UNSUPPORTED_ITERATION_PROTOCOL],
                fallback_events=[
                    unsupported_iteration_event(
                        state=state,
                        reason=ITERATION_PROTOCOL_UNAVAILABLE_REASON,
                    )
                ],
                terminal=True,
            )
    iterable = None
    if isinstance(iterator, SymbolicIterator):
        iterable = iterator.iterable
    else:
        iterable = iterator

    if isinstance(iterator, SymbolicIterator) and isinstance(iterable, SymbolicValue):
        from pysymex.execution.opcodes.common.control.sequence_iteration import (
            dispatch_sequence_getitem_iteration,
        )

        sequence_result = dispatch_sequence_getitem_iteration(
            state,
            ctx,
            iterator,
            iterable,
            target_index=target_index,
        )
        if sequence_result is not None:
            return sequence_result

    if isinstance(iterable, SymbolicObject):
        addr = iterable.address
        memory = state.memory
        if addr in memory:
            iterable = memory[addr]
    elif isinstance(iterable, SymbolicValue):
        modeled_object = getattr(iterable, "_modeled_object", None)
        if modeled_object is not None:
            iterable = modeled_object
        elif iterable.value is not None:
            iterable = iterable.value

    if isinstance(iterable, ModeledGenerator):
        generator_state = state
        if isinstance(iterator, SymbolicIterator):
            generator_state = state.fork()
            generator_state.pop()
            generator_state = generator_state.push(cast("StackValue", iterable))
        return resume_generator_for_iter(
            generator_state,
            ctx,
            iterable,
            target_index=target_index,
            continue_pc=state.pc + 1,
        )

    idx = iterator.index if isinstance(iterator, SymbolicIterator) else 0
    concrete_items: Sequence[object] | None = None
    known_len: int | None = None

    if isinstance(iterator, SymbolicIterator):
        concrete_from_iterator = concrete_iterator_items(iterator, state)
        if concrete_from_iterator is not None:
            concrete_items = cast("Sequence[object]", concrete_from_iterator)
            known_len = len(concrete_from_iterator)
    if concrete_items is None and isinstance(iterable, SymbolicList):
        concrete_from_list = iterable.concrete_items
        if concrete_from_list is not None:
            concrete_items = cast("Sequence[object]", concrete_from_list)
            known_len = len(concrete_from_list)
    elif concrete_items is None and isinstance(iterable, (str, bytes, list, tuple)):
        concrete_items = cast("Sequence[object]", iterable)
        known_len = len(concrete_items)

    if concrete_items is not None and known_len is not None:
        if idx < known_len:
            stack_item = stack_value_from_concrete_iter_item(concrete_items[idx])
            continue_state = state.fork()
            if isinstance(iterator, SymbolicIterator):
                updated_iterator = iterator.advance()
                continue_state = _state_with_iterator_update(
                    continue_state,
                    iterator,
                    updated_iterator,
                )
                continue_state.pop()
                continue_state = continue_state.push(updated_iterator)
            continue_state = continue_state.push(stack_item)
            continue_state = continue_state.advance_pc()
            return OpcodeResult.branch([continue_state])
        exit_state = state.fork()
        if isinstance(iterator, SymbolicIterator):
            exit_state = _state_with_iterator_update(
                exit_state,
                iterator,
                iterator.exhaust(),
            )
        exit_state = exit_state.push(SymbolicNone())
        exit_state = exit_state.set_pc(target_index)
        return OpcodeResult.branch([exit_state])

    if isinstance(iterable, SymbolicString):
        return _handle_symbolic_string_for_iter(
            state=state,
            iterator=iterator,
            iterable=iterable,
            idx=idx,
            target_index=target_index,
        )

    continue_state = state.fork()

    if isinstance(iterator, SymbolicIterator):
        updated_iterator = iterator.advance()
        continue_state = _state_with_iterator_update(
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
        exit_state = _state_with_iterator_update(
            exit_state,
            iterator,
            iterator.exhaust(),
        )
    exit_state = exit_state.set_pc(target_index)

    continue_state = continue_state.advance_pc()

    if isinstance(iterable, SymbolicList):
        z3_len = iterable.z3_len

        idx = iterator.index if isinstance(iterator, SymbolicIterator) else 0

        idx_expr = get_int_val(idx)
        continue_condition = idx_expr < z3_len
        exit_condition = idx_expr >= z3_len
        branches: list[VMState] = []
        known_prefix_len = known_sat_prefix_len_for_state(state)

        if branch_feasible(
            state.path_constraints,
            continue_condition,
            known_sat_prefix_len=known_prefix_len,
        ):
            continue_state = continue_state.add_constraint(continue_condition)
            continue_state = continue_state.add_constraint(
                iter_val.z3_int == iterable.element_expr_at(idx_expr)
            )

            if iterable.element_type == "int":
                continue_state = continue_state.add_constraint(iter_val.is_int == Z3_TRUE)
                continue_state = continue_state.add_constraint(iter_val.is_bool == Z3_FALSE)
                continue_state = continue_state.add_constraint(iter_val.is_float == Z3_FALSE)
                continue_state = continue_state.add_constraint(iter_val.is_str == Z3_FALSE)
                continue_state = continue_state.add_constraint(iter_val.is_obj == Z3_FALSE)
                continue_state = continue_state.add_constraint(iter_val.is_none == Z3_FALSE)
            branches.append(continue_state)

        if branch_feasible(
            state.path_constraints,
            exit_condition,
            known_sat_prefix_len=known_prefix_len,
        ):
            exit_state = exit_state.add_constraint(exit_condition)
            exit_state = exit_state.push(SymbolicNone())
            branches.append(exit_state)

        if not branches:
            return OpcodeResult.terminate()
        return OpcodeResult.branch(branches)

    continue_state = continue_state.set_pc(state.pc + 1)

    exit_state = state.fork()
    exit_state = exit_state.push(SymbolicNone())
    exit_state = exit_state.set_pc(target_index)
    return OpcodeResult.branch([continue_state, exit_state])


def _handle_symbolic_string_for_iter(
    *,
    state: VMState,
    iterator: StackValue,
    iterable: SymbolicString,
    idx: int,
    target_index: int,
) -> OpcodeResult:
    """Iterate a symbolic string with length-bound branch constraints."""
    idx_expr = get_int_val(idx)
    continue_condition = idx_expr < iterable.z3_len
    exit_condition = idx_expr >= iterable.z3_len
    exact_length = _exact_int_value(iterable.z3_len, state.path_constraints)
    branches: list[VMState] = []
    known_prefix_len = known_sat_prefix_len_for_state(state)

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
            continue_state = _state_with_iterator_update(
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
            exit_state = _state_with_iterator_update(
                exit_state,
                iterator,
                iterator.exhaust(),
            )
        exit_state = exit_state.add_constraint(exit_condition)
        exit_state = exit_state.push(SymbolicNone())
        branches.append(exit_state.set_pc(target_index))

    if not branches:
        return OpcodeResult.terminate()
    return OpcodeResult.branch(branches)


def _exact_int_value(expr: z3.ArithRef, constraints: Iterable[z3.BoolRef]) -> int | None:
    """Return a concrete integer value implied by direct equality constraints."""
    simplified = z3.simplify(expr)
    if z3.is_int_value(simplified):
        return simplified.as_long()

    known: dict[int, int] = {}
    aliases: list[tuple[z3.ExprRef, z3.ExprRef]] = []
    for constraint in _iter_conjuncts(constraints):
        constraint = z3.simplify(constraint)
        if not z3.is_eq(constraint):
            continue
        left, right = constraint.children()
        left_simplified = z3.simplify(left)
        right_simplified = z3.simplify(right)
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


def _state_with_iterator_update(
    state: VMState,
    original: SymbolicIterator,
    updated: SymbolicIterator,
) -> VMState:
    from pysymex.execution.opcodes.common.functions.classes import (
        propagate_container_mutation_reference,
    )

    return propagate_container_mutation_reference(
        state,
        original,
        cast("StackValue", updated),
    )


def _iter_conjuncts(constraints: Iterable[z3.BoolRef]) -> Iterator[z3.BoolRef]:
    """Yield top-level conjuncts from path constraints."""
    pending: list[z3.BoolRef] = list(constraints)
    while pending:
        constraint = pending.pop()
        if z3.is_and(constraint):
            pending.extend(cast("list[z3.BoolRef]", constraint.children()))
            continue
        yield constraint


def handle_common_get_iter(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Execute ``GET_ITER``: pop iterable and push an iterator object.

    Uses concrete ``iter`` when possible; otherwise wraps lists/strings/dicts or emits a
    fresh ``SymbolicIterator`` with degradation when the protocol is unknown.
    """
    if state.stack:
        obj = state.pop()
        if isinstance(obj, (CallableSentinelIterator, ModeledGenerator)):
            state = state.push(cast("StackValue", obj)).advance_pc()
            return OpcodeResult.continue_with(state)
        if isinstance(obj, SymbolicValue):
            from pysymex.execution.opcodes.common.numeric.helpers import lookup_modeled_method

            iter_method = lookup_modeled_method(obj, "__iter__")
            if iter_method is not None:
                from pysymex.execution.calls.interprocedural import (
                    perform_interprocedural_call_impl,
                )

                result = perform_interprocedural_call_impl(
                    state,
                    ctx,
                    iter_method,
                    [],
                    {},
                    protocol_method="__iter__",
                )
                if result is not None:
                    return result
                return OpcodeResult(
                    new_states=[],
                    issues=[],
                    degraded_passes=[UNSUPPORTED_ITERATION_PROTOCOL],
                    fallback_events=[
                        unsupported_iteration_event(
                            state=state,
                            reason=ITERATION_PROTOCOL_UNAVAILABLE_REASON,
                        )
                    ],
                    terminal=True,
                )
        iterator = (
            obj if isinstance(obj, SymbolicIterator) else SymbolicIterator(fresh_name("iter"), obj)
        )
        state = state.push(iterator)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


__all__ = ["handle_common_for_iter", "handle_common_get_iter"]
