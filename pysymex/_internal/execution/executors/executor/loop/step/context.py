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

"""Step execution callback assembly for executor worklist loops."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.execution.detectors.invocation.runner import run_detectors
from pysymex._internal.execution.detectors.invocation.types import DetectorRunContext
from pysymex._internal.execution.engine.line.resolution import resolve_line_number
from pysymex._internal.execution.executors.executor.events import emit_executor_event
from pysymex._internal.execution.feasibility.policy import check_path_feasibility
from pysymex._internal.execution.resources.step import check_step_depth_limit
from pysymex._internal.execution.results.context import ProcessingContext
from pysymex._internal.execution.results.processor import process_execution_result
from pysymex._internal.execution.scheduling.loop.bounds.context import LoopBoundContext
from pysymex._internal.execution.scheduling.loop.bounds.policy import apply_loop_bound_policy
from pysymex._internal.execution.scheduling.merging import offer_state_to_merger
from pysymex._internal.execution.step.context import StepExecutionContext
from pysymex._internal.stats.types import EventType

if TYPE_CHECKING:
    import dis
    from collections.abc import Callable

    from pysymex._internal.analysis.detectors.detector.contract import Detector
    from pysymex._internal.config.execution.settings import ExecutionConfig
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.session.state.core import ExecutionSession
    from pysymex._internal.execution.strategies.merger.state import StateMerger
    from pysymex._internal.limits.tracker import ResourceTracker
    from pysymex._internal.typing.protocols import SolverProtocol


@dataclass(frozen=True, slots=True)
class StepContextInputs:
    """Executor-owned fields needed to assemble one-step callbacks."""

    session: ExecutionSession
    config: ExecutionConfig
    solver: SolverProtocol
    dispatcher: OpcodeDispatcher
    hook_owner: object
    hooks: dict[str, list[Callable[..., object]]]
    resource_tracker: ResourceTracker | None
    state_merger: StateMerger | None
    detector_dispatch: dict[str, list[Detector]]
    universal_detectors: list[Detector]
    before_dispatch: Callable[[dis.Instruction, VMState, list[dis.Instruction]], None]
    on_path_complete: Callable[[VMState], None]


def build_step_context(inputs: StepContextInputs) -> StepExecutionContext:
    """Build reusable one-step execution callbacks for an executor instance."""
    loop_bound_context = LoopBoundContext(
        session=inputs.session,
        max_loop_iterations=inputs.config.max_loop_iterations,
        verbose=inputs.config.verbose,
        record_path_explored_event=lambda: emit_executor_event(EventType.PATH_EXPLORED, 1.0),
        continue_unsupported_with_host_guard=any(
            limit is not None
            for limit in (
                inputs.config.max_depth,
                inputs.config.max_iterations,
                inputs.config.timeout_seconds,
            )
        ),
    )

    def handle_loop_logic(
        current_state: VMState,
        active_instructions: list[dis.Instruction],
    ) -> bool:
        return apply_loop_bound_policy(
            loop_bound_context,
            current_state,
            active_instructions,
        )

    def check_resource_limits(current_state: VMState) -> bool:
        return check_step_depth_limit(
            session=inputs.session,
            resource_tracker=inputs.resource_tracker,
            hook_owner=inputs.hook_owner,
            hooks=inputs.hooks,
            state=current_state,
        )

    def merge_state(current_state: VMState) -> VMState | None:
        return offer_state_to_merger(
            session=inputs.session,
            state_merger=inputs.state_merger,
            state=current_state,
        )

    def path_is_feasible(current_state: VMState) -> bool:
        return check_path_feasibility(
            session=inputs.session,
            solver=inputs.solver,
            hook_owner=inputs.hook_owner,
            hooks=inputs.hooks,
            state=current_state,
        )

    def has_detectors(opname: str) -> bool:
        return bool(inputs.universal_detectors) or opname in inputs.detector_dispatch

    detector_context = DetectorRunContext(
        session=inputs.session,
        solver=inputs.solver,
        dispatcher=inputs.dispatcher,
        hook_owner=inputs.hook_owner,
        hooks=inputs.hooks,
        detector_dispatch=inputs.detector_dispatch,
        universal_detectors=inputs.universal_detectors,
        resolve_line_number=lambda pc, instructions: resolve_line_number(
            session=inputs.session,
            pc=pc,
            active_instructions=instructions,
        ),
    )

    result_context = ProcessingContext(
        session=inputs.session,
        hook_owner=inputs.hook_owner,
        hooks=inputs.hooks,
        resource_tracker=inputs.resource_tracker,
        resolve_line_number=lambda pc, instructions: resolve_line_number(
            session=inputs.session,
            pc=pc,
            active_instructions=instructions,
        ),
        on_path_complete=inputs.on_path_complete,
        record_path_explored=lambda: emit_executor_event(EventType.PATH_EXPLORED, 1.0),
    )

    return StepExecutionContext(
        session=inputs.session,
        dispatcher=inputs.dispatcher,
        hook_owner=inputs.hook_owner,
        hooks=inputs.hooks,
        root_instructions=inputs.session.instructions,
        lazy_eval_threshold=inputs.config.lazy_eval_threshold,
        check_resource_limits=check_resource_limits,
        merge_state=merge_state,
        handle_loop_logic=handle_loop_logic,
        check_path_feasibility=path_is_feasible,
        before_dispatch=inputs.before_dispatch,
        has_detectors=has_detectors,
        run_detectors=lambda current_state, instr, instructions: run_detectors(
            detector_context,
            current_state,
            instr,
            instructions,
        ),
        process_execution_result=lambda result, current_state, instructions: (
            process_execution_result(
                result_context,
                result,
                current_state,
                instructions,
            )
        ),
        on_path_complete=inputs.on_path_complete,
        get_line_number=lambda pc, instructions: resolve_line_number(
            session=inputs.session,
            pc=pc,
            active_instructions=instructions,
        ),
    )
