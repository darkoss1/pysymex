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

"""One-instruction execution step helpers."""

from __future__ import annotations

from collections.abc import Callable, Iterable, ItemsView, Mapping, Sequence
import dis
from typing import Final, Protocol, cast

from pysymex.logger import get_logger

from pysymex.core.state.record import VMState
from pysymex.execution.constants import BRANCH_OPCODES
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.session.state import ExecutionSession
from pysymex.typing import StackValue

__all__ = [
    "DUPLICATE_STATE_PRUNE_REASON",
    "build_state_key",
    "dispatch_instruction",
    "fetch_instruction",
    "is_branch_or_jump_instruction",
    "record_duplicate_branch_state",
    "record_dispatch_snapshots",
    "record_instruction_visit",
    "record_terminal_path",
    "run_post_step_hooks",
    "run_pre_step_hooks",
    "snapshot_objects",
    "snapshot_stack_mapping",
]

logger = get_logger(__name__)

HookMap = Mapping[str, Sequence[Callable[..., object]]]
DUPLICATE_STATE_PRUNE_REASON: Final = "duplicate_state"


class StackValueItems(Protocol):
    """Minimal mapping protocol for frame ``locals``/``globals`` snapshots."""

    def items(self) -> ItemsView[str, StackValue]: ...


def fetch_instruction(
    state: VMState,
    root_instructions: list[dis.Instruction],
) -> tuple[dis.Instruction | None, list[dis.Instruction]]:
    """Select the active instruction list and return the state's current instruction."""
    current = state.current_instructions
    if current is not None:
        if not current or isinstance(current[0], dis.Instruction):
            active_instructions = cast("list[dis.Instruction]", current)
        else:
            active_instructions = root_instructions
    else:
        active_instructions = root_instructions
    if state.pc >= len(active_instructions):
        return None, active_instructions
    return active_instructions[state.pc], active_instructions


def is_branch_or_jump_instruction(instr: dis.Instruction) -> bool:
    """Return whether an instruction should participate in duplicate-state pruning."""
    return instr.opname in BRANCH_OPCODES or "JUMP" in instr.opname


def build_state_key(state: VMState) -> tuple[int, ...]:
    """Build the composite key used for duplicate branch-state pruning."""
    return (
        state.hash_value(),
        state.pc,
        len(state.path_constraints),
        len(state.stack),
        len(state.call_stack),
        len(state.block_stack),
    )


def snapshot_stack_mapping(values: StackValueItems) -> dict[str, object]:
    """Shallow-copy a name-to-stack-value mapping for path snapshots."""
    return dict(values.items())


def snapshot_objects(values: Iterable[object]) -> list[object]:
    """Materialize an iterable snapshot used when recording path stacks."""
    return list(values)


def record_dispatch_snapshots(*, session: ExecutionSession, state: VMState) -> None:
    """Record globals, locals, and stack snapshots after opcode dispatch."""
    if state.call_stack:
        session.last_locals = snapshot_stack_mapping(state.call_stack[-1].local_vars)
    else:
        session.last_locals = snapshot_stack_mapping(state.local_vars)
    session.last_globals = snapshot_stack_mapping(state.global_vars)
    session.last_stack = snapshot_objects(state.stack)


def record_terminal_path(
    *,
    session: ExecutionSession,
    state: VMState,
    include_stack: bool,
    final_exception: object | None = None,
    update_exception: bool = False,
) -> None:
    """Record counters and snapshots for a terminal path."""
    session.paths_completed += 1
    session.last_branches = state.branch_trace.to_list()
    session.last_globals = snapshot_stack_mapping(state.global_vars)
    session.last_locals = snapshot_stack_mapping(state.local_vars)
    if include_stack:
        session.last_stack = snapshot_objects(state.stack)
    if update_exception:
        session.last_exception = final_exception


def record_duplicate_branch_state(
    *,
    session: ExecutionSession,
    state: VMState,
    instr: dis.Instruction,
    hook_owner: object,
    hooks: HookMap,
) -> bool:
    """Record or prune a branch/jump state using the session duplicate-state set.

    Returns:
        ``True`` when the state was pruned as a duplicate; ``False`` otherwise.
    """
    if not is_branch_or_jump_instruction(instr):
        return False

    state_key = build_state_key(state)
    if state_key in session.visited_states:
        session.paths_pruned += 1
        for hook in hooks.get("on_prune", ()):
            try:
                hook(hook_owner, state, DUPLICATE_STATE_PRUNE_REASON)
            except Exception:
                logger.exception("Plugin hook execution failed")
        return True

    session.visited_states.add(state_key)
    return False


def record_instruction_visit(*, session: ExecutionSession, state: VMState) -> bool:
    """Record that the current path reached the state's current instruction.

    Returns:
        ``True`` if the path had already visited ``state.pc``.
    """
    session.coverage.add(state.pc)
    return state.mark_visited()


def dispatch_instruction(
    *,
    dispatcher: OpcodeDispatcher,
    session: ExecutionSession,
    hook_owner: object,
    hooks: HookMap,
    instr: dis.Instruction,
    state: VMState,
) -> OpcodeResult:
    """Dispatch one opcode, snapshot the fallback state, and run post-step hooks."""
    if logger.state.trace_enabled:
        logger.trace(
            "dispatch opcode path_id=%d pc=%d offset=%d opname=%s stack=%d constraints=%d",
            state.path_id,
            state.pc,
            instr.offset,
            instr.opname,
            len(state.stack),
            len(state.path_constraints),
        )
    result = dispatcher.dispatch(instr, state)
    if logger.state.trace_enabled:
        logger.trace(
            "opcode result path_id=%d pc=%d new_states=%d issues=%d terminal=%s",
            state.path_id,
            state.pc,
            len(result.new_states),
            len(result.issues),
            result.terminal,
        )

    record_dispatch_snapshots(session=session, state=state)
    run_post_step_hooks(
        hook_owner=hook_owner,
        hooks=hooks,
        result=result,
        fallback_state=state,
        instr=instr,
    )
    return result


def run_pre_step_hooks(*, hook_owner: object, hooks: HookMap, state: VMState) -> None:
    """Run pre-step hooks before fetching or dispatching an instruction."""
    for hook in hooks.get("pre_step", ()):
        hook(hook_owner, state)


def run_post_step_hooks(
    *,
    hook_owner: object,
    hooks: HookMap,
    result: OpcodeResult,
    fallback_state: VMState,
    instr: dis.Instruction,
) -> None:
    """Run post-step hooks for successor states, logging plugin failures."""
    post_step_hooks = hooks.get("post_step")
    if not post_step_hooks:
        return
    states_to_hook = result.new_states or (fallback_state,)
    for next_state in states_to_hook:
        for hook in post_step_hooks:
            try:
                hook(hook_owner, next_state, instr)
            except Exception:
                logger.exception("Plugin hook execution failed")
