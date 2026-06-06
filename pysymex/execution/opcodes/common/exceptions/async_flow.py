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

"""Async/with/generator opcode helpers.

Covers ``BEFORE_WITH``, ``GET_AITER``, ``SEND``, ``YIELD_VALUE``, and related opcodes with
symbolic stubs where await semantics are not modeled. Does not schedule real asyncio tasks.
"""

from __future__ import annotations

import dis
from collections.abc import Sequence
from typing import TYPE_CHECKING, cast

import z3

from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.containers.sequences import SymbolicIterator
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.control.iteration_items import (
    stack_value_from_concrete_iter_item,
)
from pysymex.execution.opcodes.common.control_fallbacks import (
    UNSUPPORTED_CONTEXT_MANAGER_PROTOCOL,
    UNSUPPORTED_GENERATOR,
    unsupported_context_manager_event,
    unsupported_generator_event,
)
from pysymex.execution.opcodes.common.exceptions.groups import split_known_exception_group
from pysymex.execution.opcodes.common.exceptions.helpers import require_stack_depth
from pysymex.models.objects import SymbolicMethod
from pysymex.models.stdlib.contextlib.stubs import Suppress

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def handle_common_with_except_start(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Start of __exit__ call in with statement."""
    exit_meth = None
    for item in reversed(state.stack):
        if isinstance(item, SymbolicMethod) and item.name == "__exit__":
            exit_meth = item
            break
        if callable(item) or hasattr(item, "__self__") or hasattr(item, "__func__"):
            method = getattr(item, "method", None)
            method_name = getattr(method, "name", getattr(item, "__name__", ""))
            if method_name == "__exit__":
                exit_meth = item
                break

    if exit_meth is not None:
        exc = (
            state.peek(2) if len(state.stack) >= 3 else SymbolicValue.symbolic(f"exc_{state.pc}")[0]
        )
        modeled_exc = getattr(exc, "_modeled_object", None)
        exc_payload = modeled_exc if isinstance(modeled_exc, SymbolicException) else exc
        exc_type = cast(
            "StackValue",
            exc_payload.exc_type
            if isinstance(exc_payload, SymbolicException)
            else type(exc_payload),
        )
        receiver = getattr(exit_meth, "__self__", None)
        if isinstance(receiver, Suppress):
            state = state.push(receiver.suppresses(exc_type))
            return OpcodeResult.continue_with(state.advance_pc())
        from pysymex.execution.calls.interprocedural import (
            perform_interprocedural_call_impl,
        )

        res = perform_interprocedural_call_impl(
            state, ctx, exit_meth, [exc_type, exc, None], protocol_method="__exit__"
        )
        if res is not None:
            return res

    result, constraint = SymbolicValue.symbolic(f"with_exit_{state.pc}")
    state = state.push(result)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_before_with(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Prepare for with statement."""
    require_stack_depth(state, instr, 1, "BEFORE_WITH")
    mgr = state.pop()

    if isinstance(mgr, SymbolicValue):
        from pysymex.execution.opcodes.common.numeric.helpers import lookup_modeled_method

        enter_meth = lookup_modeled_method(mgr, "__enter__")
        exit_meth = lookup_modeled_method(mgr, "__exit__")
        if enter_meth is not None or exit_meth is not None:
            if enter_meth is None or exit_meth is None:
                return OpcodeResult(
                    new_states=[],
                    issues=[],
                    degraded_passes=[UNSUPPORTED_CONTEXT_MANAGER_PROTOCOL],
                    fallback_events=[
                        unsupported_context_manager_event(
                            state=state,
                            reason="modeled context manager is missing __enter__ or __exit__",
                        )
                    ],
                    terminal=True,
                )
            state = state.push(cast("StackValue", exit_meth))
            from pysymex.execution.calls.interprocedural import (
                perform_interprocedural_call_impl,
            )

            result = perform_interprocedural_call_impl(
                state,
                ctx,
                enter_meth,
                [],
                {},
                protocol_method="__enter__",
            )
            if result is not None:
                return result
            return OpcodeResult(
                new_states=[],
                issues=[],
                degraded_passes=[UNSUPPORTED_CONTEXT_MANAGER_PROTOCOL],
                fallback_events=[
                    unsupported_context_manager_event(
                        state=state,
                        reason="modeled context manager __enter__ could not be entered",
                    )
                ],
                terminal=True,
            )

    mgr_obj = mgr.value if isinstance(mgr, SymbolicValue) else mgr
    context_manager_result = _enter_contextlib_generator_manager(instr, state, ctx, mgr_obj)
    if context_manager_result is not None:
        return context_manager_result

    if isinstance(mgr_obj, Suppress):
        state = state.push(cast("StackValue", mgr_obj.__exit__)).push(cast("StackValue", mgr_obj))
        return OpcodeResult.continue_with(state.advance_pc())
    enter_meth = getattr(mgr_obj, "__enter__", None)
    exit_meth = getattr(mgr_obj, "__exit__", None)

    if enter_meth is not None and exit_meth is not None:
        state = state.push(exit_meth)
        from pysymex.execution.calls.interprocedural import perform_interprocedural_call

        res = perform_interprocedural_call(state, ctx, enter_meth, [])
        if res is not None:
            return res
        state.pop()

    exit_val, c1 = SymbolicValue.symbolic(f"exit_{state.pc}")
    enter_val, c2 = SymbolicValue.symbolic(f"enter_{state.pc}")
    state = state.push(exit_val)
    state = state.push(enter_val)
    state = state.add_constraint(c1)
    state = state.add_constraint(c2)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_before_async_with(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Prepare for async with statement."""
    require_stack_depth(state, instr, 1, "BEFORE_ASYNC_WITH")
    state.pop()
    exit_val, c1 = SymbolicValue.symbolic(f"async_exit_{state.pc}")
    enter_val, c2 = SymbolicValue.symbolic(f"async_enter_{state.pc}")
    state = state.push(exit_val)
    state = state.push(enter_val)
    state = state.add_constraint(c1)
    state = state.add_constraint(c2)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_end_async_for(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Execute ``END_ASYNC_FOR``: clean up async iteration state on the block stack.

    Pops the async-for block marker and advances PC; does not resume awaiting when
    the iterator is symbolic.
    """
    require_stack_depth(state, instr, 2, "END_ASYNC_FOR")
    state.pop()
    state.pop()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_get_aiter(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Execute ``GET_AITER``: pop async iterable and push ``__aiter__`` result.

    Introduces a symbolic async iterator when the protocol is not modeled.

    Limitations:
        Does not schedule awaits or interleave event-loop semantics.
    """
    require_stack_depth(state, instr, 1, "GET_AITER")
    state.pop()
    iter_val, constraint = SymbolicValue.symbolic(f"aiter_{state.pc}")
    state = state.push(iter_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_get_anext(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Get next from async iterator."""
    next_val, constraint = SymbolicValue.symbolic(f"anext_{state.pc}")
    state = state.push(next_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_get_awaitable(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Get awaitable from object."""
    require_stack_depth(state, instr, 1, "GET_AWAITABLE")
    orig_val = state.pop()
    awaitable, constraint = SymbolicValue.symbolic(f"awaitable_{state.pc}")
    state.awaitable_results[id(awaitable)] = orig_val
    state = state.push(awaitable)
    state = state.add_constraint(constraint)
    state = state.add_constraint(z3.Not(awaitable.is_none))
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _do_handle_send(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Model SEND for generator/coroutine execution."""
    _send_value = state.pop()
    awaitable = state.stack[-1]

    orig_val = state.awaitable_results.get(id(awaitable))

    target_offset = instr.argval
    target_idx = ctx.offset_to_index(int(target_offset)) if target_offset is not None else None

    iterator_result = _send_yield_from_iterator(instr, state, awaitable, target_idx)
    if iterator_result is not None:
        return iterator_result

    if orig_val is not None:
        from pysymex.execution.opcodes.common.coroutines import coroutine_resume_active

        if coroutine_resume_active(state):
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

    state_yield = state.fork()
    result_yield, constraint_yield = SymbolicValue.symbolic(f"send_{state.pc}")
    state_yield = state_yield.push(result_yield)
    state_yield = state_yield.add_constraint(constraint_yield)
    state_yield = state_yield.advance_pc()

    state_return = state.fork()
    return_val, constraint_ret = SymbolicValue.symbolic(f"await_result_{state.pc}")
    state_return = state_return.add_constraint(constraint_ret)
    state_return = state_return.push(return_val)

    if target_idx is not None:
        state_return = state_return.set_pc(target_idx)
    else:
        state_return = state_return.advance_pc()

    return OpcodeResult.branch(states=[state_yield, state_return])


def handle_common_send(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Send value to generator/coroutine."""
    require_stack_depth(state, instr, 2, "SEND")
    return _do_handle_send(instr, state, ctx)


def handle_common_yield_value(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Yield a value from a generator."""
    require_stack_depth(state, instr, 1, "YIELD_VALUE")
    from pysymex.execution.opcodes.common.coroutines import suspend_coroutine_yield_or_none

    coroutine_result = suspend_coroutine_yield_or_none(state, ctx)
    if coroutine_result is not None:
        return coroutine_result

    from pysymex.execution.opcodes.common.generators import (
        suspend_generator_yield_or_abstract,
    )

    return suspend_generator_yield_or_abstract(state, ctx)


def handle_common_end_send(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """End of generator/coroutine send."""
    require_stack_depth(state, instr, 2, "END_SEND")
    del state.stack[-2]
    state.invalidate_cached_hash()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_get_yield_from_iter(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Get iterator for yield from."""
    require_stack_depth(state, instr, 1, "GET_YIELD_FROM_ITER")
    orig_val = state.pop()
    exact_iterator = _exact_yield_from_iterator(orig_val, state)
    if exact_iterator is not None:
        state = state.push(exact_iterator)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    iter_val, constraint = SymbolicValue.symbolic(f"yield_from_{state.pc}")
    state = state.push(iter_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _enter_contextlib_generator_manager(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    manager: object,
) -> OpcodeResult | None:
    """Enter a modeled ``contextlib.contextmanager`` through VM generator semantics."""
    from pysymex.models.stdlib.contextlib.managers import ContextManager

    if not isinstance(manager, ContextManager):
        return None

    from pysymex.execution.calls.model_dispatch import apply_model
    from pysymex.execution.opcodes.common.generators import ModeledGenerator

    name = str(
        getattr(manager.function, "__name__", None)
        or getattr(manager.function, "_func_name", None)
        or "contextmanager"
    )
    generator = ModeledGenerator(
        name,
        manager.function,
        cast("tuple[StackValue, ...]", manager.args),
        tuple((key, cast("StackValue", value)) for key, value in manager.kwargs.items()),
    )
    manager.bind_modeled_generator(generator)

    state = state.push(cast("StackValue", manager.__exit__))
    return apply_model(state, next, [cast("StackValue", generator)], {}, ctx, instr)


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
    state_return = state_return.push(SymbolicNone())
    if target_idx is not None:
        state_return = state_return.set_pc(target_idx)
    else:
        state_return = state_return.advance_pc()
    return OpcodeResult.continue_with(state_return)


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


def handle_common_check_eg_match(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Check ExceptionGroup match (Python 3.11+ except* syntax)."""
    require_stack_depth(state, instr, 2, "CHECK_EG_MATCH")
    requested_type = state.pop()
    group = state.pop()
    known_split = split_known_exception_group(group, requested_type, state)
    if known_split is not None:
        rest, match = known_split
        state = state.push(rest)
        state = state.push(match)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    match_val, c1 = SymbolicValue.symbolic(f"eg_match_{state.pc}")
    rest_val, c2 = SymbolicValue.symbolic(f"eg_rest_{state.pc}")
    state = state.push(rest_val)
    state = state.push(match_val)
    state = state.add_constraint(c1)
    state = state.add_constraint(c2)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_interpreter_exit(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Exit the interpreter (Python 3.12+, for PEP 669 monitoring)."""
    return OpcodeResult.terminate()


def handle_common_return_generator(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Return a generator object (generator function entry)."""
    gen_val, constraint = SymbolicValue.symbolic(f"generator_{state.pc}")
    fallback_event = unsupported_generator_event(
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
