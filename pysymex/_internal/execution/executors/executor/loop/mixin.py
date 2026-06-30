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

"""Loop-facing executor methods for SymbolicExecutor."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.engine.worklist import WorklistLoopContext, drain_worklist
from pysymex._internal.execution.executors.executor.loop.step.context import (
    StepContextInputs,
    build_step_context,
)
from pysymex._internal.execution.executors.executor.types import ExecutorMixinContract
from pysymex._internal.execution.step.pipeline import execute_one_step

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.step.context import StepExecutionContext


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
            ),
        )

    def execute_step(self, state: VMState) -> None:
        """Execute one instruction from the worklist state through the full dispatch pipeline."""
        execute_one_step(self._build_step_context(), state)

    def _build_step_context(self) -> StepExecutionContext:
        """Build reusable one-step execution callbacks for the current executor."""
        return build_step_context(
            StepContextInputs(
                session=self.session,
                config=self.config,
                solver=self.solver,
                dispatcher=self.dispatcher,
                hook_owner=self,
                hooks=self.hooks,
                resource_tracker=self._resource_tracker,
                state_merger=self._state_merger,
                detector_dispatch=self._detector_dispatch,
                universal_detectors=self._universal_detectors,
                before_dispatch=self._before_dispatch,
                on_path_complete=self._on_path_complete,
            ),
        )
