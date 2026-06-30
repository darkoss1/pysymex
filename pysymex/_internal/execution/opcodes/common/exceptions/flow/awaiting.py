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

"""Await, async iteration, generator send, and yield-from opcode flow."""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.calls.payload import function_payload
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.generators import ModeledGenerator
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.havoc import HavocValue
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.control.fallbacks import (
    UNSUPPORTED_GENERATOR,
    flag_unsupported_generator,
)
from pysymex._internal.execution.opcodes.common.control.iteration.items import (
    stack_value_from_concrete_iter_item,
)
from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow

if TYPE_CHECKING:
    import dis
    from collections.abc import Sequence

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def handle_common_end_async_for(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Execute ``END_ASYNC_FOR`` by cleaning up async iteration state."""
    if len(state.stack) < 2:
        fallback_event = flag_unsupported_generator(
            state=state,
            reason="END_ASYNC_FOR reached without complete async iterator exception state",
        )
        while state.stack:
            state.pop()
        state = state.advance_pc()
        return OpcodeResult.continue_with(
            state,
            degraded_passes=[UNSUPPORTED_GENERATOR],
            fallback_events=[fallback_event],
        )
    state.pop()
    state.pop()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_get_aiter(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Execute ``GET_AITER``: pop async iterable and push ``__aiter__`` result.

    Introduces a symbolic async iterator when the protocol is not modeled.

    Limitations:
        Does not schedule awaits or interleave event-loop semantics.
    """
    ExceptionFlow.require_depth(state, instr, 1, "GET_AITER")
    state.pop()
    iter_val, constraint = SymbolicValue.symbolic(f"aiter_{state.pc}")
    state = state.push(iter_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_get_anext(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Get next from an async iterator as an explicitly imprecise awaitable result."""
    fallback_event = flag_unsupported_generator(
        state=state,
        reason="GET_ANEXT async iterator protocol could not be modeled precisely",
    )
    next_val, constraint = HavocValue.havoc(f"anext_{state.pc}")
    state = state.push(next_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(
        state,
        degraded_passes=[UNSUPPORTED_GENERATOR],
        fallback_events=[fallback_event],
    )


def handle_common_get_awaitable(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Get awaitable from object."""
    ExceptionFlow.require_depth(state, instr, 1, "GET_AWAITABLE")
    orig_val = state.pop()
    exact_awaitable = _modeled_generator_awaitable(orig_val)
    if exact_awaitable is not None:
        state = state.push(cast("StackValue", exact_awaitable))
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    awaitable, constraint = SymbolicValue.symbolic(f"awaitable_{state.pc}")
    state.awaitable_results[id(awaitable)] = orig_val
    state = state.push(awaitable)
    state = state.add_constraint(constraint)
    state = state.add_constraint(z3.Not(awaitable.is_none))
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _modeled_generator_awaitable(value: object) -> ModeledGenerator | None:
    """Return a modeled ``__await__`` generator for exact Python instances."""
    from pysymex._internal.core.classes.instances import SymbolicInstance
    from pysymex._internal.core.classes.types import SymbolicMethod

    instance = getattr(value, "_modeled_object", None)
    if not isinstance(instance, SymbolicInstance):
        return None
    method_obj, found = instance.get_attribute("__await__", bound_instance=value)
    if not found or not isinstance(method_obj, SymbolicMethod):
        return None
    payload = function_payload(method_obj.func)
    if payload is None or not payload.code.co_flags & inspect.CO_GENERATOR:
        return None
    args, kwargs = method_obj.get_call_args((), {})
    if kwargs:
        return None
    return ModeledGenerator(
        method_obj.name,
        payload,
        cast("tuple[StackValue, ...]", args),
        (),
    )


def handle_common_send(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Send value to generator/coroutine."""
    ExceptionFlow.require_depth(state, instr, 2, "SEND")
    return _do_handle_send(instr, state, ctx)


def _do_handle_send(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Model SEND for generator/coroutine execution."""
    sent = state.pop()
    awaitable = state.stack[-1]

    orig_val = state.awaitable_results.get(id(awaitable))

    target_offset = instr.argval
    target_idx = ctx.offset_to_index(int(target_offset)) if target_offset is not None else None

    iterator_result = _send_yield_from_iterator(instr, state, awaitable, target_idx)
    if iterator_result is not None:
        return iterator_result

    generator_result = _send_yield_from_generator(state, ctx, awaitable, sent, target_idx)
    if generator_result is not None:
        return generator_result

    if orig_val is not None:
        from pysymex._internal.execution.opcodes.common.coroutines.lifecycle import (
            coroutine_resume_active,
        )
        from pysymex._internal.execution.opcodes.common.coroutines.objects import ModeledCoroutine

        if coroutine_resume_active(state):
            if isinstance(orig_val, ModeledCoroutine):
                return _unsupported_nested_coroutine_await(state, target_idx)
            state_yield = state.fork()
            result_yield, constraint_yield = SymbolicValue.symbolic(f"await_yield_{state.pc}")
            state_yield = state_yield.push(result_yield)
            state_yield = state_yield.add_constraint(constraint_yield)
            state_yield = state_yield.advance_pc()
            return OpcodeResult.continue_with(state_yield)

        state_return = state.fork()
        state_return = state_return.push(orig_val)
        if target_idx is not None:
            state_return = state_return.set_pc(target_idx)
        else:
            state_return = state_return.advance_pc()
        return OpcodeResult.continue_with(state_return)

    fallback_event = flag_unsupported_generator(
        state=state,
        reason="SEND target could not be modeled precisely",
    )

    state_yield = state.fork()
    result_yield, constraint_yield = HavocValue.havoc(f"send_{state.pc}")
    state_yield = state_yield.push(result_yield)
    state_yield = state_yield.add_constraint(constraint_yield)
    state_yield = state_yield.advance_pc()

    state_return = state.fork()
    return_val, constraint_ret = HavocValue.havoc(f"await_result_{state.pc}")
    state_return = state_return.add_constraint(constraint_ret)
    state_return = state_return.push(return_val)

    if target_idx is not None:
        state_return = state_return.set_pc(target_idx)
    else:
        state_return = state_return.advance_pc()

    return OpcodeResult.branch(
        states=[state_yield, state_return],
        degraded_passes=[UNSUPPORTED_GENERATOR],
        fallback_events=[fallback_event],
    )


def _unsupported_nested_coroutine_await(
    state: VMState,
    target_idx: int | None,
) -> OpcodeResult:
    """Havoc a nested coroutine await inside another modeled coroutine."""
    _ = target_idx
    fallback_event = flag_unsupported_generator(
        state=state,
        reason="nested coroutine await could not be modeled precisely",
    )

    state_yield = state.fork()
    yielded, yielded_constraint = HavocValue.havoc(f"await_yield_{state.pc}")
    state_yield = state_yield.push(yielded)
    state_yield = state_yield.add_constraint(yielded_constraint)
    state_yield = state_yield.advance_pc()

    return OpcodeResult.continue_with(
        state_yield,
        degraded_passes=[UNSUPPORTED_GENERATOR],
        fallback_events=[fallback_event],
    )


def handle_common_end_send(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Finish ``SEND`` by removing the awaitable and preserving the result."""
    if len(state.stack) < 2:
        fallback_event = flag_unsupported_generator(
            state=state,
            reason="END_SEND reached without an awaitable/result stack pair",
        )
        state = state.advance_pc()
        return OpcodeResult.continue_with(
            state,
            degraded_passes=[UNSUPPORTED_GENERATOR],
            fallback_events=[fallback_event],
        )

    result = state.stack.pop()
    state.stack.pop()
    state.stack.append(result)
    state.invalidate_cached_hash()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_yield_value(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Yield a value from a generator."""
    ExceptionFlow.require_depth(state, instr, 1, "YIELD_VALUE")
    from pysymex._internal.execution.opcodes.common.coroutines.lifecycle import (
        suspend_coroutine_yield_or_none,
    )

    coroutine_result = suspend_coroutine_yield_or_none(state, ctx)
    if coroutine_result is not None:
        return coroutine_result

    from pysymex._internal.execution.opcodes.common.generators.lifecycle import (
        suspend_generator_yield_or_abstract,
    )

    return suspend_generator_yield_or_abstract(state, ctx)


def handle_common_get_yield_from_iter(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Get iterator for yield from."""
    ExceptionFlow.require_depth(state, instr, 1, "GET_YIELD_FROM_ITER")
    orig_val = state.pop()
    if isinstance(orig_val, ModeledGenerator):
        state = state.push(cast("StackValue", orig_val))
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    exact_iterator = _exact_yield_from_iterator(orig_val, state)
    if exact_iterator is not None:
        state = state.push(exact_iterator)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    fallback_event = flag_unsupported_generator(
        state=state,
        reason="yield from iterator could not be modeled precisely",
    )
    iter_val, constraint = HavocValue.havoc(f"yield_from_{state.pc}")
    state = state.push(iter_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(
        state,
        degraded_passes=[UNSUPPORTED_GENERATOR],
        fallback_events=[fallback_event],
    )


def _exact_yield_from_iterator(value: object, state: VMState) -> StackValue | None:
    """Return an exact iterator for yield-from operands whose items are known."""
    if isinstance(value, SymbolicIterator):
        return value
    resolved = _resolve_yield_from_iterable(value, state)
    if _concrete_yield_from_items(resolved) is None:
        return None
    return SymbolicIterator(f"yield_from_{state.pc}", cast("StackValue", resolved))


def _send_yield_from_iterator(
    instr: dis.Instruction,
    state: VMState,
    awaitable: object,
    target_idx: int | None,
) -> OpcodeResult | None:
    """Advance a retained exact iterator used by CPython ``yield from`` SEND."""
    if not isinstance(awaitable, SymbolicIterator):
        return None
    concrete_items = _concrete_yield_from_items(awaitable.iterable)
    if concrete_items is None:
        return None
    if awaitable.index < len(concrete_items):
        yielded = stack_value_from_concrete_iter_item(concrete_items[awaitable.index])
        state_yield = state.fork()
        state_yield.pop()
        state_yield = state_yield.push(awaitable.advance())
        state_yield = state_yield.push(yielded)
        state_yield = state_yield.advance_pc()
        return OpcodeResult.branch([state_yield])

    state_return = state.fork()
    state_return = state_return.push(SymbolicNoneType())
    if target_idx is not None:
        state_return = state_return.set_pc(target_idx)
    else:
        state_return = state_return.advance_pc()
    return OpcodeResult.continue_with(state_return)


def _send_yield_from_generator(
    state: VMState,
    ctx: OpcodeDispatcher,
    awaitable: object,
    sent: object,
    target_idx: int | None,
) -> OpcodeResult | None:
    """Resume a modeled subgenerator used by CPython ``yield from``."""
    if not isinstance(awaitable, ModeledGenerator):
        return None
    from pysymex._internal.execution.opcodes.common.generators.lifecycle import (
        resume_generator_yield_from_send,
    )

    return resume_generator_yield_from_send(
        state,
        ctx,
        awaitable,
        cast("StackValue | None", sent),
        target_index=target_idx,
        continue_pc=state.pc + 1,
    )


def _resolve_yield_from_iterable(value: object, state: VMState) -> object:
    """Resolve heap and symbolic constant wrappers for exact yield-from iteration."""
    if isinstance(value, SymbolicObject) and value.address in state.memory:
        return state.memory[value.address]
    if isinstance(value, SymbolicValue):
        modeled_object = getattr(value, "_modeled_object", None)
        if modeled_object is not None:
            return modeled_object
        if value.value is not None:
            return value.value
    return value


def _concrete_yield_from_items(value: object) -> Sequence[object] | None:
    """Return exact yield-from items for finite concrete iterables."""
    if isinstance(value, SymbolicList):
        concrete_items = value.concrete_items
        return concrete_items if concrete_items is not None else None
    if isinstance(value, (list, tuple, str, bytes)):
        return cast("Sequence[object]", value)
    return None


def handle_common_return_generator(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Return a generator object (generator function entry)."""
    gen_val, constraint = HavocValue.havoc(f"generator_{state.pc}")
    fallback_event = flag_unsupported_generator(
        state=state,
        reason="RETURN_GENERATOR created an abstract generator object",
    )
    state = state.push(gen_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(
        state,
        degraded_passes=[UNSUPPORTED_GENERATOR],
        fallback_events=[fallback_event],
    )
