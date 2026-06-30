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

"""Pre-instruction snapshot behavior for execution tracers."""

from __future__ import annotations

from time import perf_counter_ns
from typing import TYPE_CHECKING

from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from pysymex._internal.config.tracing.settings import TracerConfig
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.executors.core import SymbolicExecutor
    from pysymex._internal.typing.protocols import StackValue


logger = get_logger(__name__)


class TracerStepSnapshotMixin:
    """Pre-step snapshot capture behavior."""

    if TYPE_CHECKING:
        config: TracerConfig
        _current_state: VMState | None
        _pre_step_started_ns: int | None
        _pre_step_snapshot: (
            tuple[
                list[StackValue],
                dict[str, StackValue],
                dict[str, StackValue],
                dict[int, StackValue],
                int,
            ]
            | None
        )

    def pre_step(self, executor: SymbolicExecutor, state: VMState) -> None:
        """Capture a lightweight snapshot *before* the instruction dispatches.

        The snapshot records the current lengths/contents of stack, locals,
        globals, and memory so that ``post_step`` can compute diffs cheaply.
        The timing baseline is captured after the snapshot so instruction
        latency excludes tracing snapshot overhead.

        Args:
            executor: The running executor (for config access).
            state:    Current VM state.

        """
        if not self.config.enabled:
            return
        self._current_state = state
        try:
            stack_copy = list(state.stack)
            locals_copy = dict(state.local_vars)
            globals_copy = dict(state.global_vars)
            memory_copy = dict(state.memory)
            constraints = state.path_constraints
            count = len(constraints)
            self._pre_step_snapshot = (stack_copy, locals_copy, globals_copy, memory_copy, count)
        except Exception:
            logger.debug("Failed to capture trace pre-step snapshot", exc_info=True)
            self._pre_step_snapshot = None
        finally:
            self._pre_step_started_ns = perf_counter_ns()
