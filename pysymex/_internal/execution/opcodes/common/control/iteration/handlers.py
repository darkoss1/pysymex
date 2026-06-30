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

Builds :class:`~pysymex._internal.core.types.containers.sequences.SymbolicIterator` views over
modeled containers or introduces symbolic iteration state with
``UNSUPPORTED_ITERATION_PROTOCOL`` when ``__iter__`` is not modeled. Re-exported from
:mod:`pysymex._internal.execution.opcodes.common.control.iteration`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.base import SymbolicNoneType, fresh_name
from pysymex._internal.core.types.containers.callable_iterators import CallableSentinelIterator
from pysymex._internal.core.types.containers.generators import ModeledGenerator
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.control.iteration.concrete import (
    dispatch_concrete_for_iter,
)
from pysymex._internal.execution.opcodes.common.control.iteration.exit import (
    for_iter_exit_pops_iterator,
    for_iter_exit_uses_sentinel,
    push_for_iter_exit_sentinel,
)
from pysymex._internal.execution.opcodes.common.control.iteration.state import (
    state_with_iterator_update,
)
from pysymex._internal.execution.opcodes.common.control.iteration.structured import (
    iter_structured_iterator,
)
from pysymex._internal.execution.opcodes.common.control.iteration.symbolic import (
    iter_symbolic_list,
    iter_symbolic_string,
)
from pysymex._internal.execution.opcodes.common.functions.protocol.fallbacks import (
    ITERATION_PROTOCOL_UNAVAILABLE_REASON,
    UNSUPPORTED_ITERATION_PROTOCOL,
    flag_unsupported_iteration,
)
from pysymex._internal.execution.opcodes.common.generators.lifecycle import (
    resume_generator_for_iter,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def _for_iter_target_index(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> int:
    """Resolve the FOR_ITER jump target as an instruction index."""
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is not None:
        return target_index
    return state.pc + 2


def _unsupported_for_iter(state: VMState, reason: str) -> OpcodeResult:
    """Build a terminal unsupported-iteration result."""
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[UNSUPPORTED_ITERATION_PROTOCOL],
        fallback_events=[flag_unsupported_iteration(state=state, reason=reason)],
        terminal=True,
    )


def _iter_callable_sentinel(
    state: VMState,
    ctx: OpcodeDispatcher,
    iterator: CallableSentinelIterator,
    *,
    target_index: int,
    push_exit_sentinel: bool,
    pop_exit_iterator: bool,
) -> OpcodeResult | None:
    """Dispatch ``iter(callable, sentinel)`` iteration."""
    from pysymex._internal.execution.opcodes.common.control.iteration.callable.sentinel import (
        dispatch_callable_sentinel_iteration,
    )

    return dispatch_callable_sentinel_iteration(
        state,
        ctx,
        iterator,
        target_index=target_index,
        push_exit_sentinel=push_exit_sentinel,
        pop_exit_iterator=pop_exit_iterator,
    )


def _iter_symbolic_next(
    state: VMState,
    ctx: OpcodeDispatcher,
    iterator: SymbolicValue,
    *,
    target_index: int,
    push_exit_sentinel: bool,
    pop_exit_iterator: bool,
) -> OpcodeResult | None:
    """Dispatch modeled ``__next__`` on a symbolic iterator value."""
    from pysymex._internal.execution.opcodes.common.numeric.dunder import lookup_modeled_method

    next_method = lookup_modeled_method(iterator, "__next__")
    if next_method is None:
        return None

    from pysymex._internal.execution.calls.interprocedural.entry import (
        perform_interprocedural_call_impl,
    )
    from pysymex._internal.execution.opcodes.common.control.iteration.sequence import (
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
        protocol_retained_operand=next_iteration_retained_operand(
            target_index,
            push_exit_sentinel=push_exit_sentinel,
            pop_exit_iterator=pop_exit_iterator,
        ),
    )
    if result is not None:
        return result
    return _unsupported_for_iter(state, ITERATION_PROTOCOL_UNAVAILABLE_REASON)


def _iter_sequence_getitem(
    state: VMState,
    ctx: OpcodeDispatcher,
    iterator: SymbolicIterator,
    iterable: SymbolicValue,
    *,
    target_index: int,
    push_exit_sentinel: bool,
    pop_exit_iterator: bool,
) -> OpcodeResult | None:
    """Dispatch legacy sequence-iteration fallback through ``__getitem__``."""
    from pysymex._internal.execution.opcodes.common.control.iteration.sequence import (
        dispatch_sequence_getitem_iteration,
    )

    return dispatch_sequence_getitem_iteration(
        state,
        ctx,
        iterator,
        iterable,
        target_index=target_index,
        push_exit_sentinel=push_exit_sentinel,
        pop_exit_iterator=pop_exit_iterator,
    )


def _resolved_iterable_from_iterator(state: VMState, iterator: StackValue) -> object:
    """Resolve iterator wrappers and modeled-object indirections to the iterable payload."""
    iterable: object = iterator.iterable if isinstance(iterator, SymbolicIterator) else iterator
    if isinstance(iterable, SymbolicObject):
        addr = iterable.address
        memory = state.memory
        if addr in memory:
            return memory[addr]
    if isinstance(iterable, SymbolicValue):
        modeled_object = getattr(iterable, "_modeled_object", None)
        if modeled_object is not None:
            return modeled_object
        if iterable.value is not None:
            return iterable.value
    return iterable


def _state_with_generator_on_top(
    state: VMState,
    iterator: StackValue,
    iterable: ModeledGenerator,
) -> VMState:
    """Replace a wrapper iterator with its generator payload before resume."""
    if not isinstance(iterator, SymbolicIterator):
        return state
    generator_state = state.fork()
    generator_state.pop()
    return generator_state.push(cast("StackValue", iterable))


def _iter_modeled_generator(
    state: VMState,
    ctx: OpcodeDispatcher,
    iterator: StackValue,
    iterable: ModeledGenerator,
    *,
    target_index: int,
    push_exit_sentinel: bool,
    pop_exit_iterator: bool,
) -> OpcodeResult:
    """Resume a modeled generator through FOR_ITER."""
    return resume_generator_for_iter(
        _state_with_generator_on_top(state, iterator, iterable),
        ctx,
        iterable,
        target_index=target_index,
        continue_pc=state.pc + 1,
        push_exit_sentinel=push_exit_sentinel,
        pop_exit_iterator=pop_exit_iterator,
    )


def _iter_symbolic_iterable(
    state: VMState,
    iterator: StackValue,
    iterable: object,
    *,
    target_index: int,
    push_exit_sentinel: bool,
    pop_exit_iterator: bool,
) -> OpcodeResult | None:
    """Dispatch symbolic string/list iteration specializations."""
    if isinstance(iterable, SymbolicString):
        idx = iterator.index if isinstance(iterator, SymbolicIterator) else 0
        return iter_symbolic_string(
            state=state,
            iterator=iterator,
            iterable=iterable,
            idx=idx,
            target_index=target_index,
            push_exit_sentinel=push_exit_sentinel,
            pop_exit_iterator=pop_exit_iterator,
        )
    if isinstance(iterable, SymbolicList):
        return iter_symbolic_list(
            state,
            iterator,
            iterable,
            target_index=target_index,
            push_exit_sentinel=push_exit_sentinel,
            pop_exit_iterator=pop_exit_iterator,
        )
    return None


def handle_common_for_iter(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Iterate over a sequence with symbolic index tracking."""
    target_index = _for_iter_target_index(instr, state, ctx)
    push_exit_sentinel = for_iter_exit_uses_sentinel(ctx, target_index)
    pop_exit_iterator = for_iter_exit_pops_iterator(ctx, target_index)

    if not state.stack:
        return _unsupported_for_iter(
            state,
            "FOR_ITER requires an iterator on the VM stack",
        )

    iterator = state.peek()
    if isinstance(iterator, CallableSentinelIterator):
        callable_result = _iter_callable_sentinel(
            state,
            ctx,
            iterator,
            target_index=target_index,
            push_exit_sentinel=push_exit_sentinel,
            pop_exit_iterator=pop_exit_iterator,
        )
        if callable_result is not None:
            return callable_result

    if isinstance(iterator, SymbolicValue):
        next_result = _iter_symbolic_next(
            state,
            ctx,
            iterator,
            target_index=target_index,
            push_exit_sentinel=push_exit_sentinel,
            pop_exit_iterator=pop_exit_iterator,
        )
        if next_result is not None:
            return next_result

    iterable = iterator.iterable if isinstance(iterator, SymbolicIterator) else iterator
    if isinstance(iterator, SymbolicIterator) and isinstance(iterable, SymbolicValue):
        sequence_result = _iter_sequence_getitem(
            state,
            ctx,
            iterator,
            iterable,
            target_index=target_index,
            push_exit_sentinel=push_exit_sentinel,
            pop_exit_iterator=pop_exit_iterator,
        )
        if sequence_result is not None:
            return sequence_result

    iterable = _resolved_iterable_from_iterator(state, iterator)
    if isinstance(iterable, ModeledGenerator):
        return _iter_modeled_generator(
            state,
            ctx,
            iterator,
            iterable,
            target_index=target_index,
            push_exit_sentinel=push_exit_sentinel,
            pop_exit_iterator=pop_exit_iterator,
        )

    concrete_result = dispatch_concrete_for_iter(
        state,
        iterator,
        iterable,
        target_index=target_index,
        push_exit_sentinel=push_exit_sentinel,
        pop_exit_iterator=pop_exit_iterator,
    )
    if concrete_result is not None:
        return concrete_result

    if isinstance(iterator, SymbolicIterator):
        structured_result = iter_structured_iterator(
            state,
            iterator,
            iterable,
            target_index=target_index,
            push_exit_sentinel=push_exit_sentinel,
            pop_exit_iterator=pop_exit_iterator,
        )
        if structured_result is not None:
            return structured_result

    symbolic_result = _iter_symbolic_iterable(
        state,
        iterator,
        iterable,
        target_index=target_index,
        push_exit_sentinel=push_exit_sentinel,
        pop_exit_iterator=pop_exit_iterator,
    )
    if symbolic_result is not None:
        return symbolic_result

    return _handle_unknown_for_iter(
        state,
        iterator,
        target_index=target_index,
        push_exit_sentinel=push_exit_sentinel,
        pop_exit_iterator=pop_exit_iterator,
    )


def _handle_unknown_for_iter(
    state: VMState,
    iterator: StackValue,
    *,
    target_index: int,
    push_exit_sentinel: bool,
    pop_exit_iterator: bool,
) -> OpcodeResult:
    """Fork generic continue/exit branches for unknown iterator length."""
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
    continue_state = continue_state.set_pc(state.pc + 1)

    exit_state = state.fork()
    exit_state = push_for_iter_exit_sentinel(
        exit_state,
        push_sentinel=push_exit_sentinel,
        pop_iterator=pop_exit_iterator,
    )
    exit_state = exit_state.set_pc(target_index)
    return OpcodeResult.branch([continue_state, exit_state])


def handle_common_get_iter(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
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
            from pysymex._internal.execution.opcodes.common.numeric.dunder import (
                lookup_modeled_method,
            )

            iter_method = lookup_modeled_method(obj, "__iter__")
            if iter_method is not None:
                from pysymex._internal.execution.calls.interprocedural.entry import (
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
                        flag_unsupported_iteration(
                            state=state,
                            reason=ITERATION_PROTOCOL_UNAVAILABLE_REASON,
                        ),
                    ],
                    terminal=True,
                )
        iterator = (
            obj if isinstance(obj, SymbolicIterator) else SymbolicIterator(fresh_name("iter"), obj)
        )
        state = state.push(iterator)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_end_for(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Pop loop cleanup stack items for ``END_FOR``.

    When ``POP_TOP`` follows, remove only the ``FOR_ITER`` exit sentinel so the
    next opcode can discard the iterator. Otherwise remove both sentinel and
    iterator so later ``with`` cleanup sees the expected stack layout.
    """
    if state.stack:
        next_instr = ctx.get_instruction(state.pc + 1)
        next_is_cleanup_pop = next_instr is not None and next_instr.opname == "POP_TOP"
        top = state.stack[-1]
        if next_is_cleanup_pop and isinstance(top, SymbolicNoneType):
            state.pop()
        elif isinstance(top, SymbolicNoneType) and len(state.stack) >= 2:
            state.pop()
            if state.stack:
                state.pop()
        else:
            state.pop()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
