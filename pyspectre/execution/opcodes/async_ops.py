"""Async/Await and Coroutine opcodes for PySpectre.
Adds support for:
- GET_AWAITABLE
- GET_AITER / GET_ANEXT
- SEND / YIELD_VALUE
- END_ASYNC_FOR
- ASYNC_GEN_WRAP
- Coroutine management opcodes
"""

from __future__ import annotations
import dis
from typing import TYPE_CHECKING
from pyspectre.core.types import SymbolicNone, SymbolicValue
from pyspectre.execution.dispatcher import OpcodeResult, opcode_handler

if TYPE_CHECKING:
    from pyspectre.core.state import VMState
    from pyspectre.execution.dispatcher import OpcodeDispatcher


@opcode_handler("GET_AWAITABLE")
def handle_get_awaitable(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """
    Get awaitable object from TOS.
    Used in 'await' expression. Converts object to awaitable via __await__
    or returns directly if already a coroutine.
    """
    if state.stack:
        obj = state.pop()
    else:
        obj = SymbolicNone()
    awaitable, constraint = SymbolicValue.symbolic(f"awaitable_{state.pc}")
    state.push(awaitable)
    state.add_constraint(constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("SEND")
def handle_send(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """
    Send value into generator/coroutine.
    Pops value to send and generator, pushes yielded value.
    If generator is exhausted, jumps to target.
    """
    if len(state.stack) >= 2:
        value_to_send = state.pop()
        generator = state.pop()
    elif len(state.stack) == 1:
        generator = state.pop()
        value_to_send = SymbolicNone()
    else:
        value_to_send = SymbolicNone()
        generator = SymbolicNone()
    yielded, constraint = SymbolicValue.symbolic(f"yielded_{state.pc}")
    state.push(yielded)
    state.add_constraint(constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("YIELD_VALUE")
def handle_yield_value(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """
    Yield TOS from generator.
    Suspends the generator and returns TOS to the caller.
    """
    if state.stack:
        yielded_value = state.pop()
    else:
        yielded_value = SymbolicNone()
    state.push(SymbolicNone())
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("RESUME")
def handle_resume(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """
    Resume execution (Python 3.11+).
    Indicates generator/coroutine/async generator has been resumed.
    arg indicates context: 0=start, 1=yield, 2=await, 3=yield from.
    """
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("GET_AITER")
def handle_get_aiter(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """
    Get async iterator from TOS.
    Calls __aiter__ on the object.
    """
    if state.stack:
        obj = state.pop()
    else:
        obj = SymbolicNone()
    aiter, constraint = SymbolicValue.symbolic(f"aiter_{state.pc}")
    state.push(aiter)
    state.add_constraint(constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("GET_ANEXT")
def handle_get_anext(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """
    Get next value from async iterator.
    Pushes awaitable for __anext__ call.
    """
    if state.stack:
        aiter = state.peek()
    anext_awaitable, constraint = SymbolicValue.symbolic(f"anext_{state.pc}")
    state.push(anext_awaitable)
    state.add_constraint(constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("END_ASYNC_FOR")
def handle_end_async_for(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """
    Cleanup for async for loop on StopAsyncIteration.
    Pops exception info and async iterator.
    """
    for _ in range(3):
        if state.stack:
            state.pop()
    if state.stack:
        state.pop()
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("ASYNC_GEN_WRAP")
def handle_async_gen_wrap(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """
    Wrap value for async generator.
    Used internally by async generators.
    """
    if state.stack:
        value = state.pop()
    else:
        value = SymbolicNone()
    wrapped, constraint = SymbolicValue.symbolic(f"async_wrapped_{state.pc}")
    state.push(wrapped)
    state.add_constraint(constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("RETURN_GENERATOR")
def handle_return_generator(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """
    Create and return generator object.
    Used at the start of generator functions.
    """
    gen, constraint = SymbolicValue.symbolic(f"generator_{state.pc}")
    state.push(gen)
    state.add_constraint(constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("GEN_START")
def handle_gen_start(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """
    Start generator execution (older Python).
    Pops initial value sent to generator.
    """
    if state.stack:
        state.pop()
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("BEFORE_ASYNC_WITH")
def handle_before_async_with(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """
    Prepare for async with statement.
    Resolves __aenter__ and pushes awaitable.
    """
    if state.stack:
        mgr = state.pop()
    else:
        mgr = SymbolicNone()
    aexit, _ = SymbolicValue.symbolic(f"aexit_{state.pc}")
    state.push(aexit)
    aenter_awaitable, constraint = SymbolicValue.symbolic(f"aenter_{state.pc}")
    state.push(aenter_awaitable)
    state.add_constraint(constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("CLEANUP_THROW")
def handle_cleanup_throw(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """
    Handle exception thrown into generator during cleanup.
    """
    for _ in range(3):
        if state.stack:
            state.pop()
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("EXTENDED_ARG_QUICK")
def handle_extended_arg_quick(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """
    Extended argument prefix (Python 3.12+ optimization).
    Combines with next instruction's argument.
    """
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("CALL_INTRINSIC_1")
def handle_call_intrinsic_1(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """
    Call intrinsic function with 1 argument.
    Used for internal operations like UNARY_POSITIVE, IMPORT_STAR cleanup.
    """
    if state.stack:
        arg = state.pop()
    else:
        arg = SymbolicNone()
    result, constraint = SymbolicValue.symbolic(f"intrinsic1_{state.pc}")
    state.push(result)
    state.add_constraint(constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("CALL_INTRINSIC_2")
def handle_call_intrinsic_2(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """
    Call intrinsic function with 2 arguments.
    """
    for _ in range(2):
        if state.stack:
            state.pop()
    result, constraint = SymbolicValue.symbolic(f"intrinsic2_{state.pc}")
    state.push(result)
    state.add_constraint(constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)
