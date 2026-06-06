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

"""One-instruction execution pipeline orchestration."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import dis
from typing import cast

from pysymex.logger import get_logger

from pysymex.core.state.record import VMState
from pysymex.core.state.types import VMStateError
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.fallback import record_unsupported_vm_state
from pysymex.execution.feasibility import (
    should_check_pending_constraints,
)
from pysymex.execution.session.state import ExecutionSession
from pysymex.execution.step import (
    dispatch_instruction,
    fetch_instruction,
    record_duplicate_branch_state,
    record_instruction_visit,
    record_terminal_path,
    run_pre_step_hooks,
)

logger = get_logger(__name__)

HookMap = Mapping[str, Sequence[Callable[..., object]]]
BeforeDispatch = Callable[[dis.Instruction, VMState, list[dis.Instruction]], None]
CheckPathFeasibility = Callable[[VMState], bool]
CheckResourceLimits = Callable[[VMState], bool]
GetLineNumber = Callable[[int, list[dis.Instruction]], int | None]
HandleLoopLogic = Callable[[VMState, list[dis.Instruction]], bool]
MergeState = Callable[[VMState], VMState | None]
OnPathComplete = Callable[[VMState], None]
ProcessExecutionResult = Callable[[OpcodeResult, VMState, list[dis.Instruction]], None]
RunDetectors = Callable[[VMState, dis.Instruction, list[dis.Instruction]], None]
HasDetectors = Callable[[str], bool]


@dataclass(frozen=True, slots=True)
class StepExecutionContext:
    """Executor callbacks and mutable owners needed for one instruction step."""

    session: ExecutionSession
    dispatcher: OpcodeDispatcher
    hook_owner: object
    hooks: HookMap
    root_instructions: list[dis.Instruction]
    lazy_eval_threshold: int
    check_resource_limits: CheckResourceLimits
    merge_state: MergeState
    handle_loop_logic: HandleLoopLogic
    check_path_feasibility: CheckPathFeasibility
    before_dispatch: BeforeDispatch
    has_detectors: HasDetectors
    run_detectors: RunDetectors
    process_execution_result: ProcessExecutionResult
    on_path_complete: OnPathComplete
    get_line_number: GetLineNumber


def execute_one_step(context: StepExecutionContext, state: VMState) -> None:
    """Execute one worklist state through the step pipeline."""
    run_pre_step_hooks(hook_owner=context.hook_owner, hooks=context.hooks, state=state)

    instr, active_instructions = fetch_instruction(state, context.root_instructions)

    if instr is None:
        if logger.state.trace_enabled:
            logger.trace("path complete path_id=%d pc=%d", state.path_id, state.pc)
        record_terminal_path(
            session=context.session,
            state=state,
            include_stack=False,
        )
        context.on_path_complete(state)
        return

    if not context.check_resource_limits(state):
        return
    context.dispatcher.set_instructions(active_instructions)
    state.current_instructions = cast("list[object]", active_instructions)

    merged = context.merge_state(state)
    if merged is None:
        return
    if merged is not state:
        state = merged

    if not context.handle_loop_logic(state, active_instructions):
        return

    if record_duplicate_branch_state(
        session=context.session,
        state=state,
        instr=instr,
        hook_owner=context.hook_owner,
        hooks=context.hooks,
    ):
        return

    record_instruction_visit(session=context.session, state=state)

    if should_check_pending_constraints(
        state=state,
        lazy_eval_threshold=context.lazy_eval_threshold,
    ):
        if not context.check_path_feasibility(state):
            return

    context.before_dispatch(instr, state, active_instructions)
    if context.has_detectors(instr.opname):
        context.run_detectors(state, instr, active_instructions)

    try:
        result = dispatch_instruction(
            dispatcher=context.dispatcher,
            session=context.session,
            hook_owner=context.hook_owner,
            hooks=context.hooks,
            instr=instr,
            state=state,
        )
        context.process_execution_result(result, state, active_instructions)
    except VMStateError as exc:
        line_no = context.get_line_number(state.pc, active_instructions)
        record_unsupported_vm_state(
            session=context.session,
            state=state,
            exc=exc,
            line_number=line_no,
            record_degraded_passes=context.session.record_degraded_passes,
        )
        return
    except Exception as exc:
        logger.error("Engine failure at PC %d: %s", state.pc, exc, exc_info=True)
        raise
