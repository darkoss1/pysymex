"""Stack manipulation opcodes."""

from __future__ import annotations
import dis
from typing import TYPE_CHECKING
from pyspectre.core.types import SymbolicNone
from pyspectre.execution.dispatcher import OpcodeResult, opcode_handler

if TYPE_CHECKING:
    from pyspectre.core.state import VMState
    from pyspectre.execution.dispatcher import OpcodeDispatcher


@opcode_handler("POP_TOP")
def handle_pop_top(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Discard top of stack."""
    if state.stack:
        state.pop()
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("DUP_TOP")
def handle_dup_top(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Duplicate top of stack."""
    if state.stack:
        state.push(state.peek())
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("DUP_TOP_TWO")
def handle_dup_top_two(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Duplicate the two top-most stack items."""
    if len(state.stack) >= 2:
        a = state.peek(0)
        b = state.peek(1)
        state.push(b)
        state.push(a)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("ROT_TWO")
def handle_rot_two(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Swap the two top-most stack items."""
    if len(state.stack) >= 2:
        state.stack[-1], state.stack[-2] = state.stack[-2], state.stack[-1]
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("ROT_THREE")
def handle_rot_three(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Rotate three stack items: TOP, SECOND, THIRD -> SECOND, THIRD, TOP."""
    if len(state.stack) >= 3:
        top = state.pop()
        state.stack.insert(-2, top)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("ROT_FOUR")
def handle_rot_four(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Rotate four stack items."""
    if len(state.stack) >= 4:
        top = state.pop()
        state.stack.insert(-3, top)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("COPY")
def handle_copy(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Copy the i-th item to the top of stack (Python 3.11+)."""
    idx = int(instr.argval)
    if len(state.stack) >= idx:
        state.push(state.stack[-idx])
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("SWAP")
def handle_swap(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Swap top of stack with i-th item (Python 3.11+)."""
    idx = int(instr.argval)
    if len(state.stack) >= idx:
        state.stack[-1], state.stack[-idx] = state.stack[-idx], state.stack[-1]
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("NOP", "RESUME")
def handle_nop(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """No operation."""
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("PUSH_NULL")
def handle_push_null(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Push NULL onto stack (Python 3.11+ for CALL)."""
    null_val = SymbolicNone()
    state.push(null_val)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("CACHE")
def handle_cache(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Cache instruction - skip."""
    state.pc += 1
    return OpcodeResult.continue_with(state)
