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

"""Canonical SymbolicExecutor implementation assembled from execution owners.

This module owns the concrete ``SymbolicExecutor`` class, which wires executor
entrypoints, loop callbacks, lifecycle, feasibility, result processing, and
detector table/invocation owners into a single public executor.

The class is responsible for:
- Loading CPython-version-appropriate opcode handlers at construction time.
- Initialising the incremental Z3 solver, the opcode dispatcher, and optional
  sub-systems (state merger, cross-function analyser, result cache, resource tracker).
- Driving the path-exploration loop via ``execute_function`` / ``execute_code``.
- Exposing plugin hooks (``add_detector``, ``register_handler``,
  ``register_hook``) for external extension.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.defaults import default_registry
from pysymex._internal.execution.detectors.tables import add_detector_to_dispatch
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.executors.executor.bootstrap import (
    build_executor_infrastructure,
    resolve_execution_config,
)
from pysymex._internal.execution.executors.executor.entrypoints.mixin import ExecutorEntrypointMixin
from pysymex._internal.execution.executors.executor.loop.mixin import ExecutorLoopMixin
from pysymex._internal.execution.strategies.merger.state import StateMerger
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    import dis
    from collections.abc import Callable

    from pysymex._internal.analysis.detectors.detector.contract import Detector
    from pysymex._internal.analysis.detectors.detector.registry import DetectorRegistry
    from pysymex._internal.config.execution.settings import ExecutionConfig
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.types import OpcodeHandler
    from pysymex._internal.typing.protocols import SolverProtocol

logger = get_logger(__name__)


class SymbolicExecutor(
    ExecutorEntrypointMixin,
    ExecutorLoopMixin,
):
    """Main symbolic execution engine.

    Composes two executor method layers into the canonical engine entry point:
    ``ExecutorEntrypointMixin`` (``execute_function`` / ``execute_code``),
    and ``ExecutorLoopMixin`` (engine worklist adapter and per-step dispatch).
    Path feasibility is owned by :mod:`pysymex._internal.execution.feasibility`; opcode
    result processing is owned by :mod:`pysymex._internal.execution.results.processor`;
    detector dispatch tables are owned by :mod:`pysymex._internal.execution.detectors.tables`,
    and per-instruction detector invocation is owned by
    :mod:`pysymex._internal.execution.detectors.invocation`.

    At each conditional branch an opcode handler returns two ``VMState``
    successor states which are queued for exploration. The path manager
    (``AdaptivePathManager`` by default) schedules successor states through the
    default POLAR runtime queue; explicit fallback modes can still use
    POLAR runtime queueing. Infeasible paths are pruned lazily by Z3 once
    the pending constraint accumulation threshold is reached.

    Per-run mutable state is owned by ``ExecutionSession`` and reset through
    :mod:`pysymex._internal.execution.engine.lifecycle` before each new analysis. Plugin
    hooks and dynamic handler registration are supported via ``register_hook`` /
    ``register_handler``.
    """

    def __init__(
        self,
        config: ExecutionConfig | None = None,
        detector_registry: DetectorRegistry | None = None,
        **config_overrides: object,
    ) -> None:
        """Initialize solver, dispatcher, detectors, and optional subsystems.

        Args:
            config: Execution limits and feature flags. When ``None``, built from
                ``config_overrides`` keyword arguments.
            detector_registry: Detector registry; defaults to the global registry.
            **config_overrides: Field overrides applied when ``config`` is provided
                or used to construct a fresh ``ExecutionConfig``.

        Side Effects:
            Loads opcode handlers and constructs an ``IncrementalSolver``.

        """
        self.config = resolve_execution_config(config, config_overrides)
        from pysymex._internal.execution.opcodes.registry import load_opcode_handlers

        load_opcode_handlers()
        self.detector_registry = detector_registry or default_registry
        self.dispatcher = OpcodeDispatcher()
        self.dispatcher.config = self.config
        infrastructure = build_executor_infrastructure(
            config=self.config,
            detector_registry=self.detector_registry,
            dispatcher=self.dispatcher,
            state_merger_factory=StateMerger,
        )
        self.solver: SolverProtocol = infrastructure.solver
        self.session = infrastructure.session
        self._result_cache = infrastructure.result_cache
        self._state_merger = infrastructure.state_merger
        self._resource_tracker = infrastructure.resource_tracker
        self._cross_function = infrastructure.cross_function
        self.interaction_graph = infrastructure.interaction_graph
        self._active_detectors = infrastructure.active_detectors
        self._detector_dispatch = infrastructure.detector_dispatch
        self._universal_detectors = infrastructure.universal_detectors
        self._result_cache_version = 0
        self._infrastructure_degraded_passes: list[str] = []

        self.hooks: dict[str, list[Callable[..., object]]] = {}

    def add_detector(self, detector: Detector) -> None:
        """Append a detector and register it for runtime dispatch.

        Universal detectors are consulted on every instruction dispatch.
        Opcode-specific detectors are only consulted for their declared
        ``relevant_opcodes``. Install detectors before starting execution to
        guarantee full-run coverage.
        """
        self._active_detectors.append(detector)
        add_detector_to_dispatch(
            detector=detector,
            detector_dispatch=self._detector_dispatch,
            universal_detectors=self._universal_detectors,
        )
        self._result_cache_version += 1

    def register_handler(self, opcode: str, handler: OpcodeHandler) -> None:
        """Register a dynamic opcode handler with the dispatcher.

        Delegates to ``OpcodeDispatcher.register_handler``. The handler
        replaces any existing registration for ``opcode``.
        """
        self.dispatcher.register_handler(opcode, handler)
        self._result_cache_version += 1

    def register_hook(self, hook_name: str, handler: Callable[..., object]) -> None:
        """Append a callback to a named hook list.

        Supported hook names: ``"pre_step"``, ``"post_step"``, ``"on_fork"``,
        ``"on_issue"``, ``"on_prune"``.
        """
        self.hooks.setdefault(hook_name, []).append(handler)
        self._result_cache_version += 1

    def _before_dispatch(
        self,
        instr: dis.Instruction,
        state: VMState,
        active_instructions: list[dis.Instruction],
    ) -> None:
        """No-op extension point called immediately before opcode dispatch.

        Subclasses may override this to inspect or prepare state before the
        normal dispatch path runs. The base implementation does nothing.
        """
        _ = instr
        _ = state
        _ = active_instructions

    def _on_path_complete(self, state: VMState) -> None:
        """No-op extension point called when a symbolic path terminates.

        Subclasses may override this to observe path completion. The base
        implementation does nothing and does not mutate ``state``.
        """
        _ = state
