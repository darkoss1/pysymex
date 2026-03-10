"""Exception handling opcodes."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

from pysymex.core.types import SymbolicValue
from pysymex.execution.dispatcher import OpcodeResult, opcode_handler

if TYPE_CHECKING:
    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher

_RAISING_OPS = frozenset(
    {
        "CALL",
        "CALL_FUNCTION",
        "CALL_METHOD",
        "CALL_FUNCTION_EX",
        "CALL_KW",
        "BINARY_SUBSCR",
        "STORE_SUBSCR",
        "DELETE_SUBSCR",
        "BINARY_TRUE_DIVIDE",
        "BINARY_FLOOR_DIVIDE",
        "BINARY_MODULO",
        "LOAD_ATTR",
        "STORE_ATTR",
        "DELETE_ATTR",
        "IMPORT_NAME",
        "IMPORT_FROM",
        "RAISE_VARARGS",
        "RERAISE",
        "BINARY_OP",
        "LOAD_GLOBAL",
        "UNPACK_SEQUENCE",
        "FOR_ITER",
    }
)


def _try_block_can_raise(ctx: OpcodeDispatcher, start_pc: int, handler_pc: int) -> bool:
    """Check whether the try-body between start_pc and handler_pc contains
    any instruction that could potentially raise an exception.

    Returns True if the try body may raise, False if it provably cannot.
    """
    instructions = ctx.instructions
    for pc_idx in range(start_pc, min(handler_pc, len(instructions))):
        if instructions[pc_idx].opname in _RAISING_OPS:
            return True
    return False


@opcode_handler("SETUP_FINALLY")
def handle_setup_finally(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Set up a try/finally block by pushing a handler onto the block stack.

    Does **not** eagerly fork execution paths.  The exception state will
    be forked lazily when a raising opcode (e.g. ``RAISE_VARARGS``,
    ``CALL``) is actually encountered, or when the executor's
    ``_fork_for_exception`` helper fires.

    This avoids the exponential path-explosion caused by forking at
    every ``try:`` entry, especially in code with deeply-nested or
    back-to-back exception handlers.
    """
    from pysymex.core.state import BlockInfo

    handler_offset = instr.argval
    handler_pc = None
    if handler_offset is not None:
        handler_pc = ctx.offset_to_index(handler_offset)

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


@opcode_handler("POP_BLOCK")
def handle_pop_block(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Pop a block from the block stack."""
    state.exit_block()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("PUSH_EXC_INFO")
def handle_push_exc_info(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Push exception info onto the stack (Python 3.11+)."""
    exc_val, constraint = SymbolicValue.symbolic(f"exc_{state .pc }")
    state = state.push(exc_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("POP_EXCEPT")
def handle_pop_except(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Pop exception handler block."""
    state.exit_block()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("CHECK_EXC_MATCH")
def handle_check_exc_match(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Check if exception matches (Python 3.11+).

    Correctly models the type hierarchy: catching ``ValueError`` also catches
    ``UnicodeDecodeError``, etc.  When the exception type is purely symbolic
    the result is left as a symbolic boolean so both paths are explored.
    """
    if len(state.stack) >= 2:
        state.pop()
    result, constraint = SymbolicValue.symbolic(f"exc_match_{state .pc }")
    state = state.push(result)
    state = state.add_constraint(constraint)
    state = state.add_constraint(result.is_bool)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("CLEANUP_THROW")
def handle_cleanup_throw(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Clean up after generator.throw() (Python 3.12+)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("RERAISE")
def handle_reraise(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Re-raise the current exception."""
    return OpcodeResult.terminate()


@opcode_handler("WITH_EXCEPT_START")
def handle_with_except_start(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Start of __exit__ call in with statement."""
    result, constraint = SymbolicValue.symbolic(f"with_exit_{state .pc }")
    state = state.push(result)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("BEFORE_WITH")
def handle_before_with(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Prepare for with statement (Python 3.11+)."""
    if state.stack:
        _ = state.pop()
        exit_val, c1 = SymbolicValue.symbolic(f"exit_{state .pc }")
        state = state.push(exit_val)
        state = state.add_constraint(c1)
        enter_val, c2 = SymbolicValue.symbolic(f"enter_{state .pc }")
        state = state.push(enter_val)
        state = state.add_constraint(c2)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("BEFORE_ASYNC_WITH")
def handle_before_async_with(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Prepare for async with statement."""
    if state.stack:
        state.pop()
    exit_val, c1 = SymbolicValue.symbolic(f"async_exit_{state .pc }")
    enter_val, c2 = SymbolicValue.symbolic(f"async_enter_{state .pc }")
    state = state.push(exit_val)
    state = state.push(enter_val)
    state = state.add_constraint(c1)
    state = state.add_constraint(c2)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("END_ASYNC_FOR")
def handle_end_async_for(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """End of async for loop."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("GET_AITER")
def handle_get_aiter(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Get async iterator."""
    if state.stack:
        state.pop()
    iter_val, constraint = SymbolicValue.symbolic(f"aiter_{state .pc }")
    state = state.push(iter_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("GET_ANEXT")
def handle_get_anext(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Get next from async iterator."""
    next_val, constraint = SymbolicValue.symbolic(f"anext_{state .pc }")
    state = state.push(next_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("GET_AWAITABLE")
def handle_get_awaitable(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Get awaitable from object."""
    if state.stack:
        state.pop()
    awaitable, constraint = SymbolicValue.symbolic(f"awaitable_{state .pc }")
    state = state.push(awaitable)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("SEND")
def handle_send(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Send value to generator/coroutine."""
    if len(state.stack) >= 2:
        state.pop()
        state.pop()
    result, constraint = SymbolicValue.symbolic(f"send_{state .pc }")
    state = state.push(result)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("YIELD_VALUE")
def handle_yield_value(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Yield a value from a generator."""
    if state.stack:
        state.pop()
    sent, constraint = SymbolicValue.symbolic(f"yield_sent_{state .pc }")
    state = state.push(sent)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("END_SEND")
def handle_end_send(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """End of generator send (Python 3.12+)."""
    if len(state.stack) >= 2:
        state.pop()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("GET_YIELD_FROM_ITER")
def handle_get_yield_from_iter(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Get iterator for yield from."""
    if state.stack:
        state.pop()
    iter_val, constraint = SymbolicValue.symbolic(f"yield_from_{state .pc }")
    state = state.push(iter_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("CHECK_EG_MATCH")
def handle_check_eg_match(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Check ExceptionGroup match (Python 3.11+ except* syntax)."""
    if len(state.stack) >= 2:
        state.pop()
        state.pop()
    match_val, c1 = SymbolicValue.symbolic(f"eg_match_{state .pc }")
    rest_val, c2 = SymbolicValue.symbolic(f"eg_rest_{state .pc }")
    state = state.push(rest_val)
    state = state.push(match_val)
    state = state.add_constraint(c1)
    state = state.add_constraint(c2)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("EXIT_INIT_CHECK")
def handle_exit_init_check(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Check __init__ returned None (Python 3.12+)."""
    if state.stack:
        state.pop()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("SETUP_CLEANUP")
def handle_setup_cleanup(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Set up cleanup handler (Python 3.12+)."""
    from pysymex.core.state import BlockInfo

    handler_offset = instr.argval
    if handler_offset is not None:
        handler_pc = ctx.offset_to_index(handler_offset)
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


@opcode_handler("INTERPRETER_EXIT")
def handle_interpreter_exit(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Exit the interpreter (Python 3.12+, for PEP 669 monitoring)."""
    return OpcodeResult.terminate()


@opcode_handler("RETURN_GENERATOR")
def handle_return_generator(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Return a generator object (generator function entry)."""
    gen_val, constraint = SymbolicValue.symbolic(f"generator_{state .pc }")
    state = state.push(gen_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
