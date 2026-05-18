# pysymex: Python Symbolic Execution & Formal Verification
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

"""Common exception handling opcodes."""

from __future__ import annotations

import dis
from collections.abc import Iterable
from typing import TYPE_CHECKING

import z3

from pysymex.core.state import VMStateError
from pysymex.core.types import SymbolicNone, SymbolicValue
from pysymex.execution.dispatcher import OpcodeResult

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher


def _require_stack_depth(
    state: VMState,
    instr: dis.Instruction,
    required_depth: int,
    purpose: str,
) -> None:
    """Enforce minimum stack depth for opcode execution."""
    if len(state.stack) < required_depth:
        raise VMStateError(
            f"{instr.opname} at pc {state.pc}: stack depth {len(state.stack)} "
            f"cannot satisfy {required_depth} item(s) for {purpose}"
        )


_MISSING_ITEMS = object()


def _find_exception_entry(ctx: OpcodeDispatcher, offset: int) -> object | None:
    """Return the CPython exception-table entry covering *offset*."""
    entries = getattr(ctx, "_exception_entries", ())
    best_entry: object | None = None
    best_start: int | None = None
    best_end: int | None = None
    for entry in entries:
        start = getattr(entry, "start", None)
        end = getattr(entry, "end", None)
        target = getattr(entry, "target", None)
        if start is None or end is None or target is None:
            continue
        if start <= offset < end:
            if best_start is None:
                best_entry = entry
                best_start = start
                best_end = end
                continue
            if start > best_start:
                best_entry = entry
                best_start = start
                best_end = end
                continue
            if start == best_start and best_end is not None and end < best_end:
                best_entry = entry
                best_end = end
    return best_entry


def _is_exception_handler_target(ctx: OpcodeDispatcher, offset: int) -> bool:
    """Return whether *offset* is an exception-table handler entry point."""
    entries = getattr(ctx, "_exception_entries", ())
    for entry in entries:
        target = getattr(entry, "target", None)
        if target == offset:
            return True
    return False


def jump_to_exception_handler(
    state: VMState,
    ctx: OpcodeDispatcher,
    offset: int,
    exc: StackValue,
) -> VMState | None:
    """Construct the stack shape CPython expects at an exception handler."""
    entry = _find_exception_entry(ctx, offset)
    if entry is None:
        return None
    target = getattr(entry, "target", None)
    if target is None:
        return None
    handler_pc = ctx.offset_to_index(int(target))
    if handler_pc is None:
        return None

    depth_obj = getattr(entry, "depth", 0)
    depth = depth_obj if isinstance(depth_obj, int) and depth_obj > 0 else 0
    preserved = list(state.stack[:depth])

    next_state = state.set_pc(handler_pc)
    next_state.stack = type(state.stack)(preserved)
    next_state = next_state.push(exc)
    if bool(getattr(entry, "lasti", False)):
        next_state = next_state.push(SymbolicValue.from_const(offset))
    return next_state


def _materialize_exception_items(exc_types_obj: object) -> list[object]:
    """Normalize exception type payloads to a plain list."""
    raw_items_attr = getattr(exc_types_obj, "_concrete_items", _MISSING_ITEMS)
    raw_items_obj: object = exc_types_obj if raw_items_attr is _MISSING_ITEMS else raw_items_attr
    if raw_items_obj is None:
        return []
    if isinstance(raw_items_obj, (str, bytes, dict)):
        return [raw_items_obj]
    if isinstance(raw_items_obj, Iterable):
        return [raw_items_obj]
    return [raw_items_obj]


def handle_common_setup_finally(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Set up a try/finally block by pushing a handler onto the block stack."""
    from pysymex.core.state import BlockInfo

    handler_offset = instr.argval
    handler_pc = None
    if handler_offset is not None:
        handler_pc = ctx.offset_to_index(int(handler_offset))

    if handler_pc is not None:
        state.enter_block(
            BlockInfo(
                block_type="finally",
                start_pc=state.pc,
                end_pc=handler_pc,
                handler_pc=handler_pc,
            )
        )

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_pop_block(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Pop a block from the block stack."""
    state.exit_block()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_push_exc_info(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Push exception info onto the stack."""
    if not state.stack and _is_exception_handler_target(ctx, instr.offset):
        return OpcodeResult.terminate()
    _require_stack_depth(state, instr, 1, "PUSH_EXC_INFO")
    exc = state.pop()
    state = state.push(SymbolicNone("old_exc"))
    state = state.push(exc)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_pop_except(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Pop exception handler block."""
    _require_stack_depth(state, instr, 1, "POP_EXCEPT")
    state.pop()

    block = state.current_block()
    if block and block.block_type in ("except", "finally"):
        state.exit_block()

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_check_exc_match(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Check if exception matches."""
    _require_stack_depth(state, instr, 2, "CHECK_EXC_MATCH")
    exc_types = state.pop()
    exc = state.stack[-1]

    if exc is not None and exc_types is not None:
        exc_name = str(getattr(exc, "name", ""))

        def _matches(t: object) -> bool:
            t_name = t.__name__ if isinstance(t, type) else str(t)
            return (
                t_name in {"BaseException", "Exception"}
                or t_name == exc_name
                or (bool(exc_name) and (t_name in exc_name or exc_name in t_name))
            )

        match_found = False
        exc_types_obj: object = exc_types
        items = _materialize_exception_items(exc_types_obj)
        if items:
            match_found = any(_matches(t) for t in items)
        else:
            match_found = _matches(exc_types)

        exc_types_name = exc_types_obj.__name__ if isinstance(exc_types_obj, type) else ""
        if match_found or exc_types_name in {"BaseException", "Exception"}:
            state = state.push(SymbolicValue.from_const(True))
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)

    result, constraint = SymbolicValue.symbolic(f"exc_match_{state.pc}")
    state = state.push(result)
    state = state.add_constraint(constraint)
    state = state.add_constraint(result.is_bool)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_cleanup_throw(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Clean up after generator.throw()."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_reraise(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Re-raise the current exception."""
    oparg = instr.argval
    if not state.stack:
        return OpcodeResult.terminate()
    exc = state.pop()

    if oparg is not None and int(oparg) > 0:
        if state.stack:
            state.pop()

    handler_state = jump_to_exception_handler(state, ctx, instr.offset, exc)
    if handler_state is not None:
        return OpcodeResult.continue_with(handler_state)

    block = state.current_block()
    if block and block.block_type in ("finally", "except", "cleanup"):
        if block.handler_pc is not None:
            state = state.set_pc(block.handler_pc)
            state.stack = type(state.stack)()
            state = state.push(exc)
            return OpcodeResult.continue_with(state)

    return OpcodeResult.terminate()


def handle_common_with_except_start(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Start of __exit__ call in with statement."""
    result, constraint = SymbolicValue.symbolic(f"with_exit_{state.pc}")
    state = state.push(result)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_before_with(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Prepare for with statement."""
    _require_stack_depth(state, instr, 1, "BEFORE_WITH")
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
    _require_stack_depth(state, instr, 1, "BEFORE_ASYNC_WITH")
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
    """End of async for loop."""
    _require_stack_depth(state, instr, 2, "END_ASYNC_FOR")
    state.pop()
    state.pop()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_get_aiter(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Get async iterator."""
    _require_stack_depth(state, instr, 1, "GET_AITER")
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
    _require_stack_depth(state, instr, 1, "GET_AWAITABLE")
    orig_val = state.pop()
    awaitable, constraint = SymbolicValue.symbolic(f"awaitable_{state.pc}")
    state.awaitable_results[id(awaitable)] = orig_val
    state = state.push(awaitable)
    state = state.add_constraint(constraint)
    state = state.add_constraint(z3.Not(awaitable.is_none))
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _do_handle_send(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Model SEND for generator/coroutine execution.

    Stack before SEND:
        [..., receiver, send_value]

    Yield/suspend path:
        [..., receiver, yielded_value]
        pc advances to the next instruction.

    Return/StopIteration path:
        [..., receiver, return_value]
        pc jumps to instr.argval, normally END_SEND.

    END_SEND later removes the receiver below the return value.
    """
    _send_value = state.pop()
    awaitable = state.stack[-1]

    orig_val = state.awaitable_results.get(id(awaitable))

    target_offset = instr.argval
    target_idx = ctx.offset_to_index(int(target_offset)) if target_offset is not None else None

    # If the awaitable has a completed synchronous return value, continue only on the return path.
    if orig_val is not None:
        state_return = state.fork()
        state_return = state_return.push(orig_val)
        if target_idx is not None:
            state_return = state_return.set_pc(target_idx)
        else:
            state_return = state_return.advance_pc()
        return OpcodeResult.continue_with(state_return)

    # Path 1: the generator/coroutine yields or suspends.
    state_yield = state.fork()
    result_yield, constraint_yield = SymbolicValue.symbolic(f"send_{state.pc}")
    state_yield = state_yield.push(result_yield)
    state_yield = state_yield.add_constraint(constraint_yield)
    state_yield = state_yield.advance_pc()

    # Path 2: the generator/coroutine returns via StopIteration.
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
    _require_stack_depth(state, instr, 2, "SEND")
    return _do_handle_send(instr, state, ctx)


def handle_common_yield_value(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Yield a value from a generator."""
    _require_stack_depth(state, instr, 1, "YIELD_VALUE")
    state.pop()
    sent, constraint = SymbolicValue.symbolic(f"yield_sent_{state.pc}")
    state = state.push(sent)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_end_send(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """End of generator/coroutine send.

    END_SEND removes the receiver/generator below the result, leaving
    the yielded/returned value on top of the stack.
    """
    _require_stack_depth(state, instr, 2, "END_SEND")
    del state.stack[-2]
    state._cached_hash = None  # type: ignore[reportPrivateUsage]
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_get_yield_from_iter(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Get iterator for yield from."""
    _require_stack_depth(state, instr, 1, "GET_YIELD_FROM_ITER")
    state.pop()
    iter_val, constraint = SymbolicValue.symbolic(f"yield_from_{state.pc}")
    state = state.push(iter_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_check_eg_match(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Check ExceptionGroup match (Python 3.11+ except* syntax)."""
    _require_stack_depth(state, instr, 2, "CHECK_EG_MATCH")
    state.pop()
    state.pop()
    match_val, c1 = SymbolicValue.symbolic(f"eg_match_{state.pc}")
    rest_val, c2 = SymbolicValue.symbolic(f"eg_rest_{state.pc}")
    state = state.push(rest_val)
    state = state.push(match_val)
    state = state.add_constraint(c1)
    state = state.add_constraint(c2)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_setup_cleanup(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Set up cleanup handler (Python 3.12+)."""
    from pysymex.core.state import BlockInfo

    handler_offset = instr.argval
    if handler_offset is not None:
        handler_pc = ctx.offset_to_index(int(handler_offset))
        if handler_pc is not None:
            state.enter_block(
                BlockInfo(
                    block_type="cleanup",
                    start_pc=state.pc,
                    end_pc=handler_pc,
                    handler_pc=handler_pc,
                )
            )
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_interpreter_exit(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Exit the interpreter (Python 3.12+, for PEP 669 monitoring)."""
    return OpcodeResult.terminate()


def handle_common_raise_varargs(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle exception raising, distinguishing caught vs uncaught."""
    argc = int(instr.argval) if instr.argval is not None else 0
    _require_stack_depth(state, instr, argc, "RAISE_VARARGS")
    exc = None
    for _ in range(argc):
        exc = state.pop()

    if exc is not None:
        handler_state = jump_to_exception_handler(state, ctx, instr.offset, exc)
        if handler_state is not None:
            return OpcodeResult.continue_with(handler_state)

    block = state.current_block()
    if block and block.block_type in ("finally", "except", "cleanup"):
        if block.handler_pc is not None:
            state = state.set_pc(block.handler_pc)
            state.stack = type(state.stack)()
            if exc is not None:
                state = state.push(exc)
            return OpcodeResult.continue_with(state)

    return OpcodeResult.terminate()


def handle_common_return_generator(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Return a generator object (generator function entry)."""
    gen_val, constraint = SymbolicValue.symbolic(f"generator_{state.pc}")
    state = state.push(gen_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_setup_with(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Setup with block."""
    _require_stack_depth(state, instr, 1, "SETUP_WITH")
    state.pop()

    exit_val, tc1 = SymbolicValue.symbolic(f"exit_{state.pc}")
    enter_val, tc2 = SymbolicValue.symbolic(f"enter_{state.pc}")

    state = state.push(exit_val)
    state = state.push(enter_val)
    state = state.add_constraint(tc1)
    state = state.add_constraint(tc2)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
