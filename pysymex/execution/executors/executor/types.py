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

"""Shared executor type aliases and mixin contracts."""

from __future__ import annotations

from collections.abc import Callable
import dis
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from pysymex.analysis.runtime.cache import LRUCache
    from pysymex.analysis.static.cross_function import CrossFunctionAnalyzer
    from pysymex.analysis.detectors import Detector, DetectorRegistry
    from pysymex.analysis.static.types import TypeAnalyzer
    from pysymex.core.graph.cig import ConstraintInteractionGraph
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
    from pysymex.execution.session.state import ExecutionSession
    from pysymex.execution.strategies.merger.state import StateMerger
    from pysymex.execution.config.settings import ExecutionConfig
    from pysymex.execution.results.result import ExecutionResult
    from pysymex.resources.tracker import ResourceTracker
    from pysymex.typing import SolverProtocol

    class ExecutorMixinContract(Protocol):
        """Structural protocol listing attributes mixed into ``SymbolicExecutor``."""

        config: ExecutionConfig
        detector_registry: DetectorRegistry
        dispatcher: OpcodeDispatcher
        solver: SolverProtocol
        session: ExecutionSession
        hooks: dict[str, list[Callable[..., object]]]
        interaction_graph: ConstraintInteractionGraph
        _active_detectors: list[Detector]
        _cross_function: CrossFunctionAnalyzer | None
        _detector_dispatch: dict[str, list[Detector]]
        _effect_summaries: dict[str, object]
        _infrastructure_degraded_passes: list[str]
        _resource_tracker: ResourceTracker | None
        _result_cache: LRUCache[str, ExecutionResult] | None
        _result_cache_version: int
        _state_merger: StateMerger | None
        _type_analyzer: TypeAnalyzer | None
        _universal_detectors: list[Detector]

        def _before_dispatch(
            self,
            instr: dis.Instruction,
            state: VMState,
            active_instructions: list[dis.Instruction],
        ) -> None: ...

        def _on_path_complete(self, state: VMState) -> None: ...

        def execute_function(
            self,
            func: Callable[..., object],
            symbolic_args: dict[str, str] | None = None,
            initial_values: dict[str, object] | None = None,
        ) -> ExecutionResult: ...

        def execute_loop(self) -> None: ...

        def execute_step(self, state: VMState) -> None: ...

else:

    class ExecutorMixinContract:
        pass
