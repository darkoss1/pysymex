"""Exception handling opcodes."""

from __future__ import annotations
import dis
from typing import TYPE_CHECKING
from pyspectre.core.types import SymbolicValue
from pyspectre.execution.dispatcher import OpcodeResult, opcode_handler

if TYPE_CHECKING:
    from pyspectre.core.state import VMState
    from pyspectre.execution.dispatcher import OpcodeDispatcher

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
    """Set up a try/finally block with precision-guided forking.

    Only forks execution when the try body contains operations that can
    actually raise. If the try body is provably non-raising (only
    assignments, constants, arithmetic), continues linearly to avoid
    path explosion.
    """
    from pyspectre.core.state import BlockInfo

    handler_offset = instr.argval
    handler_pc = None
    if handler_offset is not None:
        handler_pc = ctx.offset_to_index(handler_offset)

    if handler_pc is not None:
        can_raise = _try_block_can_raise(ctx, state.pc + 1, handler_pc)

        normal_state = state.fork()
        normal_state.enter_block(
            BlockInfo(
                block_type="finally",
                start_pc=state.pc,
                end_pc=handler_pc,
                handler_pc=handler_pc,
            )
        )
        normal_state.pc = state.pc + 1

        if can_raise:
            exc_state = state.fork()
            exc_val, constraint = SymbolicValue.symbolic(f"exception_{state.pc}")
            exc_state.push(exc_val)
            exc_state.add_constraint(constraint)
            exc_state.pc = handler_pc
            return OpcodeResult.branch([normal_state, exc_state])

        return OpcodeResult.continue_with(normal_state)

    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("POP_BLOCK")
def handle_pop_block(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Pop a block from the block stack."""
    state.exit_block()
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("PUSH_EXC_INFO")
def handle_push_exc_info(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Push exception info onto the stack (Python 3.11+)."""
    exc_val, constraint = SymbolicValue.symbolic(f"exc_{state.pc}")
    state.push(exc_val)
    state.add_constraint(constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("POP_EXCEPT")
def handle_pop_except(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Pop exception handler block."""
    state.exit_block()
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("CHECK_EXC_MATCH")
def handle_check_exc_match(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Check if exception matches (Python 3.11+)."""
    if len(state.stack) >= 2:
        state.pop()
    result, constraint = SymbolicValue.symbolic(f"exc_match_{state.pc}")
    state.push(result)
    state.add_constraint(constraint)
    state.add_constraint(result.is_bool)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("CLEANUP_THROW")
def handle_cleanup_throw(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Clean up after generator.throw() (Python 3.12+)."""
    state.pc += 1
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
    result, constraint = SymbolicValue.symbolic(f"with_exit_{state.pc}")
    state.push(result)
    state.add_constraint(constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("BEFORE_WITH")
def handle_before_with(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Prepare for with statement (Python 3.11+)."""
    if state.stack:
        _ = state.pop()
        exit_val, c1 = SymbolicValue.symbolic(f"exit_{state.pc}")
        state.push(exit_val)
        state.add_constraint(c1)
        enter_val, c2 = SymbolicValue.symbolic(f"enter_{state.pc}")
        state.push(enter_val)
        state.add_constraint(c2)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("BEFORE_ASYNC_WITH")
def handle_before_async_with(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Prepare for async with statement."""
    if state.stack:
        state.pop()
    exit_val, c1 = SymbolicValue.symbolic(f"async_exit_{state.pc}")
    enter_val, c2 = SymbolicValue.symbolic(f"async_enter_{state.pc}")
    state.push(exit_val)
    state.push(enter_val)
    state.add_constraint(c1)
    state.add_constraint(c2)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("END_ASYNC_FOR")
def handle_end_async_for(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """End of async for loop."""
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("GET_AITER")
def handle_get_aiter(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Get async iterator."""
    if state.stack:
        state.pop()
    iter_val, constraint = SymbolicValue.symbolic(f"aiter_{state.pc}")
    state.push(iter_val)
    state.add_constraint(constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("GET_ANEXT")
def handle_get_anext(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Get next from async iterator."""
    next_val, constraint = SymbolicValue.symbolic(f"anext_{state.pc}")
    state.push(next_val)
    state.add_constraint(constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("GET_AWAITABLE")
def handle_get_awaitable(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Get awaitable from object."""
    if state.stack:
        state.pop()
    awaitable, constraint = SymbolicValue.symbolic(f"awaitable_{state.pc}")
    state.push(awaitable)
    state.add_constraint(constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("SEND")
def handle_send(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Send value to generator/coroutine."""
    if len(state.stack) >= 2:
        state.pop()
        state.pop()
    result, constraint = SymbolicValue.symbolic(f"send_{state.pc}")
    state.push(result)
    state.add_constraint(constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("YIELD_VALUE")
def handle_yield_value(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Yield a value from a generator."""
    if state.stack:
        state.pop()
    sent, constraint = SymbolicValue.symbolic(f"yield_sent_{state.pc}")
    state.push(sent)
    state.add_constraint(constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("END_SEND")
def handle_end_send(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """End of generator send (Python 3.12+)."""
    if len(state.stack) >= 2:
        state.pop()
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("GET_YIELD_FROM_ITER")
def handle_get_yield_from_iter(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Get iterator for yield from."""
    if state.stack:
        state.pop()
    iter_val, constraint = SymbolicValue.symbolic(f"yield_from_{state.pc}")
    state.push(iter_val)
    state.add_constraint(constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("CHECK_EG_MATCH")
def handle_check_eg_match(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Check ExceptionGroup match (Python 3.11+ except* syntax)."""
    if len(state.stack) >= 2:
        state.pop()
        state.pop()
    match_val, c1 = SymbolicValue.symbolic(f"eg_match_{state.pc}")
    rest_val, c2 = SymbolicValue.symbolic(f"eg_rest_{state.pc}")
    state.push(rest_val)
    state.push(match_val)
    state.add_constraint(c1)
    state.add_constraint(c2)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("EXIT_INIT_CHECK")
def handle_exit_init_check(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Check __init__ returned None (Python 3.12+)."""
    if state.stack:
        state.pop()
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("SETUP_CLEANUP")
def handle_setup_cleanup(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Set up cleanup handler (Python 3.12+)."""
    from pyspectre.core.state import BlockInfo

    handler_offset = instr.argval
    if handler_offset is not None and ctx.offset_to_index(handler_offset) is not None:
        handler_pc = ctx.offset_to_index(handler_offset)
        state.enter_block(
            BlockInfo(
                block_type="cleanup",
                start_pc=state.pc,
                end_pc=handler_pc,
                handler_pc=handler_pc,
            )
        )
    state.pc += 1
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
    gen_val, constraint = SymbolicValue.symbolic(f"generator_{state.pc}")
    state.push(gen_val)
    state.add_constraint(constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)
