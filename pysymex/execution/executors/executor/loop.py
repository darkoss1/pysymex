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

"""Loop-facing executor methods for SymbolicExecutor.

Owns the executor method adapters and callback assembly for the engine worklist
loop and the one-state step pipeline (``execute_step``), resource-limit
enforcement through ``execution.resources``, and duplicate-state pruning through
the step owner. Loop-bound and widening handoff policy lives in
``execution.scheduling.loop_bounds``; state-merger step handoff lives in
``execution.scheduling.merging``. Detector dispatch is delegated to the
``execution.detectors.invocation`` owner.
"""

from __future__ import annotations

import dis

from pysymex.core.state.record import VMState
from pysymex.execution.detectors.invocation import DetectorRunContext, run_detectors
from pysymex.execution.engine import resolve_line_number
from pysymex.execution.engine.worklist import WorklistLoopContext, drain_worklist
from pysymex.execution.executors.executor.events import emit_event
from pysymex.execution.executors.executor.types import ExecutorMixinContract
from pysymex.execution.feasibility import check_path_feasibility
from pysymex.execution.resources import check_step_depth_limit
from pysymex.execution.results.processor import (
    ResultProcessingContext,
    process_execution_result,
)
from pysymex.execution.scheduling.loop_bounds import LoopBoundContext, apply_loop_bound_policy
from pysymex.execution.scheduling.merging import offer_state_to_merger
from pysymex.execution.step.pipeline import (
    StepExecutionContext,
    execute_one_step,
)
from pysymex.stats.types import EventType


class ExecutorLoopMixin(ExecutorMixinContract):
    """Worklist-loop and one-state-step adapters for the public executor."""

    def execute_loop(self) -> None:
        """Drain the worklist through the engine-owned outer loop."""
        step_context = self._build_step_context()
        drain_worklist(
            WorklistLoopContext(
                session=self.session,
                config=self.config,
                solver=self.solver,
                resource_tracker=self._resource_tracker,
                execute_step=lambda state: execute_one_step(step_context, state),
                record_degraded_passes=self.session.record_degraded_passes,
            )
        )

    def execute_step(self, state: VMState) -> None:
        """Execute one instruction from the worklist state through the full dispatch pipeline.

        Pipeline (short-circuits return on failure at each gate):
        1. Fires ``"pre_step"`` hooks.
        2. Fetches the current instruction via ``fetch_instruction``; if
           ``instr`` is ``None`` (PC past end), records path completion,
           snapshots locals/globals/branches, calls ``_on_path_complete``, and
           returns.
        3. Checks the depth resource limit via ``execution.resources``; returns
           if pruned.
        4. Syncs the dispatcher's instruction list and ``state.current_instructions``.
        5. If state merging is active, offers the state to
           ``execution.scheduling.merging``; prunes if absorbed, continues with
           the merged state if merged.
        6. Calls ``execution.scheduling.loop_bounds``; returns if the state is
           pruned by the loop bound.
        7. Deduplicates at branch/jump instructions through ``execution.step``;
           returns if the key is already in the session duplicate-state set.
        8. Records the PC in session coverage and marks the state visited.
        9. Checks pending-constraint threshold (``lazy_eval_threshold``); if
           exceeded, runs a path-feasibility check and returns on infeasible.
        10. Calls ``_before_dispatch``, then detector invocation owner.
        11. Dispatches the opcode through ``execution.step``; snapshots
            globals/locals/stack and fires ``"post_step"`` hooks.
        13. Calls ``execution.results.processor`` to route successors into the
            worklist and publish opcode-result issues.

        On ``VMStateError`` emits an ``IssueKind.UNKNOWN`` issue, increments
        ``paths_pruned``, and records ``"unsupported_vm_state"`` as a degraded
        pass. Unexpected exceptions are re-raised after logging at ERROR level.
        """
        execute_one_step(self._build_step_context(), state)

    def _build_step_context(self) -> StepExecutionContext:
        """Build reusable one-step execution callbacks for the current executor."""
        loop_bound_context = LoopBoundContext(
            session=self.session,
            max_loop_iterations=self.config.max_loop_iterations,
            verbose=self.config.verbose,
            record_path_explored_event=lambda: emit_event(EventType.PATH_EXPLORED, 1.0),
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
                session=self.session,
                resource_tracker=self._resource_tracker,
                record_degraded_passes=self.session.record_degraded_passes,
                hook_owner=self,
                hooks=self.hooks,
                state=current_state,
            )

        def merge_state(current_state: VMState) -> VMState | None:
            return offer_state_to_merger(
                session=self.session,
                state_merger=self._state_merger,
                state=current_state,
            )

        def path_is_feasible(current_state: VMState) -> bool:
            return check_path_feasibility(
                session=self.session,
                solver=self.solver,
                hook_owner=self,
                hooks=self.hooks,
                state=current_state,
            )

        def has_detectors(opname: str) -> bool:
            return bool(self._universal_detectors) or opname in self._detector_dispatch

        detector_context = DetectorRunContext(
            session=self.session,
            solver=self.solver,
            dispatcher=self.dispatcher,
            hook_owner=self,
            hooks=self.hooks,
            detector_dispatch=self._detector_dispatch,
            universal_detectors=self._universal_detectors,
            resolve_line_number=lambda pc, instructions: resolve_line_number(
                session=self.session,
                pc=pc,
                active_instructions=instructions,
            ),
        )

        result_context = ResultProcessingContext(
            session=self.session,
            hook_owner=self,
            hooks=self.hooks,
            resource_tracker=self._resource_tracker,
            resolve_line_number=lambda pc, instructions: resolve_line_number(
                session=self.session,
                pc=pc,
                active_instructions=instructions,
            ),
            on_path_complete=self._on_path_complete,
            record_path_explored=lambda: emit_event(EventType.PATH_EXPLORED, 1.0),
        )

        context = StepExecutionContext(
            session=self.session,
            dispatcher=self.dispatcher,
            hook_owner=self,
            hooks=self.hooks,
            root_instructions=self.session.instructions,
            lazy_eval_threshold=self.config.lazy_eval_threshold,
            check_resource_limits=check_resource_limits,
            merge_state=merge_state,
            handle_loop_logic=handle_loop_logic,
            check_path_feasibility=path_is_feasible,
            before_dispatch=self._before_dispatch,
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
            on_path_complete=self._on_path_complete,
            get_line_number=lambda pc, instructions: resolve_line_number(
                session=self.session,
                pc=pc,
                active_instructions=instructions,
            ),
        )
        return context
