"""Async/Await and Coroutine opcodes for pysymex.
Adds support for:
- ASYNC_GEN_WRAP
- GEN_START
- EXTENDED_ARG_QUICK

Note: Most async opcodes (GET_AWAITABLE, SEND, YIELD_VALUE, GET_AITER,
GET_ANEXT, END_ASYNC_FOR, RETURN_GENERATOR, BEFORE_ASYNC_WITH,
CLEANUP_THROW, RESUME, CALL_INTRINSIC_1, CALL_INTRINSIC_2) are
registered in exceptions.py and control.py respectively.
"""

from __future__ import annotations


import dis

from typing import TYPE_CHECKING


from pysymex.core.types import SymbolicValue

from pysymex.execution.dispatcher import OpcodeResult, opcode_handler

if TYPE_CHECKING:
    from pysymex.core.state import VMState

    from pysymex.execution.dispatcher import OpcodeDispatcher


@opcode_handler("ASYNC_GEN_WRAP")
def handle_async_gen_wrap(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """
    Wrap value for async generator.
    Used internally by async generators.
    """

    if state.stack:
        state.pop()

    wrapped, constraint = SymbolicValue.symbolic(f"async_wrapped_{state.pc}")

    state.push(wrapped)

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
