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

"""Exception block-stack and active-exception opcode handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow

if TYPE_CHECKING:
    import dis
    from collections.abc import Sequence

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def handle_common_setup_finally(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Set up a try/finally block by pushing a handler onto the block stack."""
    from pysymex._internal.core.state.types import BlockInfo

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
            ),
        )

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_pop_block(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Pop a block from the block stack."""
    state.exit_block()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_push_exc_info(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Push exception info onto the stack."""
    if not state.stack and ExceptionFlow.is_handler_at(ctx, instr.offset):
        return OpcodeResult.terminate()
    ExceptionFlow.require_depth(state, instr, 1, "PUSH_EXC_INFO")
    exc = state.pop()
    state.active_exception = _active_exception_for_push_exc_info(exc, state.stack)
    state.pending_reraise_exception = None
    state.invalidate_cached_hash()
    state = state.push(SymbolicNoneType("old_exc"))
    state = state.push(exc)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_pop_except(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Pop exception handler block."""
    ExceptionFlow.require_depth(state, instr, 1, "POP_EXCEPT")
    state.pop()
    state.active_exception = None
    state.invalidate_cached_hash()
    next_instr = ctx.get_instruction(state.pc + 1)
    if state.deferred_detector_issues and (next_instr is None or next_instr.opname != "RERAISE"):
        state.deferred_detector_issues = []
        state.invalidate_cached_hash()

    block = state.current_block()
    if block and block.block_type in ("except", "finally"):
        state.exit_block()

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_setup_cleanup(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Set up cleanup handler (Python 3.12+)."""
    from pysymex._internal.core.state.types import BlockInfo

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
                ),
            )
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _active_exception_for_push_exc_info(
    pushed_value: StackValue,
    remaining_stack: Sequence[StackValue],
) -> StackValue | None:
    """Return the active exception when CPython lasti metadata is above it."""
    if _is_exception_stack_value(pushed_value):
        return pushed_value
    if remaining_stack and _is_exception_stack_value(remaining_stack[-1]):
        return remaining_stack[-1]
    return pushed_value


def _is_exception_stack_value(value: object) -> bool:
    """Return whether *value* can represent the currently handled exception."""
    if isinstance(value, (BaseException, SymbolicException)):
        return True
    if isinstance(value, type):
        return issubclass(value, BaseException)
    modeled_value = getattr(value, "_modeled_object", None)
    return isinstance(modeled_value, SymbolicException)
