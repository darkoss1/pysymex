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

import dis
from collections.abc import Callable
from typing import TYPE_CHECKING, cast

from pysymex.analysis.runtime.cache import LRUCache
from pysymex.analysis.static.cross_function import CrossFunctionAnalyzer
from pysymex.analysis.detectors import (
    Detector,
    DetectorRegistry,
    default_registry,
)
from pysymex.analysis.static.types import TypeAnalyzer
from pysymex.core.graph.cig import ConstraintInteractionGraph
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.state.record import VMState
from pysymex.execution.config.settings import ExecutionConfig
from pysymex.execution.detectors.tables import (
    add_detector_to_dispatch,
    build_detector_runtime_tables,
)
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher, OpcodeHandler
from pysymex.execution.executors.executor.entrypoints import ExecutorEntrypointMixin
from pysymex.execution.detectors.query.cache import DETECTOR_QUERY_CACHE_MAX_ENTRIES
from pysymex.execution.executors.executor.events import emit_event
from pysymex.execution.executors.executor.loop import ExecutorLoopMixin
from pysymex.execution.initial_state.types import SymbolicCreatedValue
from pysymex.execution.results.result import ExecutionResult
from pysymex.execution.session.state import ExecutionSession
from pysymex.execution.strategies.merger.state import StateMerger
from pysymex.execution.strategies.merger.types import MergePolicy
from pysymex.logger import get_logger
from pysymex.resources.mapping import resource_limits_from_execution_config
from pysymex.resources.tracker import ResourceTracker

if TYPE_CHECKING:
    from pysymex.typing import SolverProtocol

logger = get_logger(__name__)


class SymbolicExecutor(
    ExecutorEntrypointMixin,
    ExecutorLoopMixin,
):
    """Main symbolic execution engine.

    Composes two executor method layers into the canonical engine entry point:
    ``ExecutorEntrypointMixin`` (``execute_function`` / ``execute_code``),
    and ``ExecutorLoopMixin`` (engine worklist adapter and per-step dispatch).
    Path feasibility is owned by :mod:`pysymex.execution.feasibility`; opcode
    result processing is owned by :mod:`pysymex.execution.results.processor`;
    detector dispatch tables are owned by :mod:`pysymex.execution.detectors.tables`,
    and per-instruction detector invocation is owned by
    :mod:`pysymex.execution.detectors.invocation`.

    At each conditional branch an opcode handler returns two ``VMState``
    successor states which are queued for exploration. The path manager
    (``AdaptivePathManager`` by default) schedules successor states through the
    default POLAR runtime queue; explicit fallback modes can still use
    POLAR runtime queueing. Infeasible paths are pruned lazily by Z3 once
    the pending constraint accumulation threshold is reached.

    Per-run mutable state is owned by ``ExecutionSession`` and reset through
    :mod:`pysymex.execution.engine.lifecycle` before each new analysis. Plugin
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
        if config is None:
            config_ctor = cast("Callable[..., ExecutionConfig]", ExecutionConfig)
            self.config = config_ctor(**config_overrides)
        elif config_overrides:
            from dataclasses import replace as _dc_replace

            self.config = _dc_replace(config, **config_overrides)
        else:
            self.config = config
        from pysymex.execution.opcodes import load_opcode_handlers

        load_opcode_handlers()
        self.detector_registry = detector_registry or default_registry
        self.dispatcher = OpcodeDispatcher()
        setattr(self.dispatcher, "config", self.config)
        self.solver: SolverProtocol = IncrementalSolver(
            timeout_ms=self.config.solver_timeout_ms,
            use_cache=self.config.enable_solver_cache,
        )
        self.session = ExecutionSession()
        self._result_cache: LRUCache[str, ExecutionResult] | None = None
        self._state_merger: StateMerger | None = None
        self._resource_tracker: ResourceTracker | None = None
        self._cross_function: CrossFunctionAnalyzer | None = None
        self._type_analyzer: TypeAnalyzer | None = None
        self._result_cache_version = 0
        self._effect_summaries: dict[str, object] = {}
        self._infrastructure_degraded_passes: list[str] = []
        from pysymex.core.solver.independence.optimizer import ConstraintIndependenceOptimizer

        self._independence_optimizer = ConstraintIndependenceOptimizer()
        self.interaction_graph = ConstraintInteractionGraph(self._independence_optimizer)

        self.session.reset_phase_stats()
        self.session.reset_last_execution_snapshots()
        if self.config.enable_caching:
            self._result_cache = LRUCache[str, ExecutionResult](maxsize=500)
        if self.config.enable_state_merging:
            policy_map = {
                "conservative": MergePolicy.CONSERVATIVE,
                "moderate": MergePolicy.MODERATE,
                "aggressive": MergePolicy.AGGRESSIVE,
            }
            self._state_merger = StateMerger(
                policy=policy_map.get(self.config.merge_policy, MergePolicy.MODERATE)
            )
        if self.config.enable_cross_function:
            self._cross_function = CrossFunctionAnalyzer()
            self.dispatcher.cross_function = self._cross_function

        self._resource_tracker = ResourceTracker(
            limits=resource_limits_from_execution_config(self.config),
        )

        detector_tables = build_detector_runtime_tables(
            config=self.config,
            detector_registry=self.detector_registry,
        )
        self._active_detectors: list[Detector] = detector_tables.active_detectors
        self._detector_dispatch: dict[str, list[Detector]] = detector_tables.detector_dispatch
        self._universal_detectors: list[Detector] = detector_tables.universal_detectors

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
        self, instr: dis.Instruction, state: VMState, active_instructions: list[dis.Instruction]
    ) -> None:
        """No-op extension point called immediately before opcode dispatch.

        Subclasses (``AsyncSymbolicExecutor``, ``ConcurrentSymbolicExecutor``)
        override this to intercept async opcodes or concurrency events before
        the normal dispatch path runs. The base implementation does nothing.
        """
        _ = instr
        _ = state
        _ = active_instructions

    def _on_path_complete(self, state: VMState) -> None:
        """No-op extension point called when a symbolic path terminates.

        ``AsyncSymbolicExecutor`` overrides this to mark the current coroutine
        as completed in the symbolic event loop. The base implementation does
        nothing and does not mutate ``state``.
        """
        _ = state


__all__ = [
    "SymbolicExecutor",
    "SymbolicCreatedValue",
    "emit_event",
    "DETECTOR_QUERY_CACHE_MAX_ENTRIES",
]
