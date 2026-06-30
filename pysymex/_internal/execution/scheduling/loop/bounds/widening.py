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

"""Loop-widening exit-state handoff."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import LoopCounterKey
    from pysymex._internal.execution.scheduling.loop.bounds.context import LoopBoundContext
    from pysymex._internal.execution.scheduling.loops.types import LoopInfo

logger = get_logger(__name__)


def try_widen_loop_state(
    context: LoopBoundContext,
    state: VMState,
    active_instructions: list[dis.Instruction],
    loop: LoopInfo,
    pc_key: LoopCounterKey,
    *,
    require_progress_evidence: bool = True,
) -> bool:
    """Try to enqueue a widened loop-exit state for a changing recurrence."""
    widening = context.session.loop_widening
    prev_state = state.prev_loop_states.get(pc_key)
    if (
        widening is None
        or prev_state is None
        or not loop.exit_pcs
        or (require_progress_evidence and not widening.should_widen(prev_state, state, loop))
    ):
        return False

    widened = widening.widen_state(prev_state, state, loop)
    max_body_offset = max(loop.body_pcs) if loop.body_pcs else loop.header_pc
    exit_idx = resolve_loop_exit_index(
        active_instructions=active_instructions,
        loop=loop,
        max_body_offset=max_body_offset,
    )
    if exit_idx is not None:
        widened = widened.set_pc(exit_idx)
        widened = _prepare_widened_loop_exit_stack(widened, active_instructions, exit_idx, loop)
    else:
        widened = widened.set_pc(len(active_instructions))

    unwind_loop_blocks(widened, loop, max_body_offset)
    if context.session.worklist:
        context.session.worklist.add_state(widened)
    context.session.paths_explored += 1
    context.record_path_explored_event()
    if context.verbose:
        logger.debug("Loop at PC %s: widened and jumped to exit", pc_key)
    context.session.paths_pruned += 1
    return True


def _prepare_widened_loop_exit_stack(
    widened: VMState,
    active_instructions: list[dis.Instruction],
    exit_idx: int,
    loop: LoopInfo,
) -> VMState:
    """Preserve CPython ``FOR_ITER`` exit stack shape for widened loop exits."""
    if exit_idx >= len(active_instructions):
        return widened
    header = _instruction_at_offset(active_instructions, loop.header_pc)
    if header is None or header.opname != "FOR_ITER":
        return widened
    exit_opname = active_instructions[exit_idx].opname
    if exit_opname == "END_FOR":
        return widened.push(SymbolicNoneType("loop_widened_exit"))
    if exit_opname == "POP_TOP":
        return widened
    if widened.stack and isinstance(widened.stack[-1], SymbolicIterator):
        widened.pop()
    return widened


def _instruction_at_offset(
    active_instructions: list[dis.Instruction],
    offset: int,
) -> dis.Instruction | None:
    """Return the active instruction at *offset*, if present."""
    for instruction in active_instructions:
        if instruction.offset == offset:
            return instruction
    return None


def resolve_loop_exit_index(
    *,
    active_instructions: list[dis.Instruction],
    loop: LoopInfo,
    max_body_offset: int,
) -> int | None:
    """Return the instruction index that resumes after a widened loop body."""
    for idx, instruction in enumerate(active_instructions):
        if instruction.offset > max_body_offset:
            return idx

    for exit_pc in sorted(loop.exit_pcs):
        for idx, instruction in enumerate(active_instructions):
            if instruction.offset == exit_pc:
                return idx
    return None


def unwind_loop_blocks(widened: VMState, loop: LoopInfo, max_body_offset: int) -> None:
    """Pop block-stack entries scoped to the widened loop body."""
    while widened.block_stack:
        top_block = widened.block_stack[-1]
        if top_block.start_pc >= loop.header_pc and top_block.end_pc <= max_body_offset + 1:
            widened.exit_block()
        else:
            break
