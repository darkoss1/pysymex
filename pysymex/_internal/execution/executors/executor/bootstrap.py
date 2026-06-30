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

"""Constructor-time infrastructure assembly for the symbolic executor."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, cast

from pysymex._internal.analysis.runtime.cache.memory import LRUCache
from pysymex._internal.config.execution.settings import ExecutionConfig
from pysymex._internal.core.graph.cig import ConstraintInteractionGraph
from pysymex._internal.core.solver.engine.incremental import IncrementalSolver
from pysymex._internal.execution.calls.cross.function.analyzer import CrossFunctionAnalyzer
from pysymex._internal.execution.detectors.tables import build_detector_runtime_tables
from pysymex._internal.execution.results.result import ExecutionResult
from pysymex._internal.execution.session.state.core import ExecutionSession
from pysymex._internal.execution.strategies.merger.types import MergePolicy
from pysymex._internal.limits.mapping import limits_from_execution_config
from pysymex._internal.limits.tracker import ResourceTracker

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.analysis.detectors.detector.contract import Detector
    from pysymex._internal.analysis.detectors.detector.registry import DetectorRegistry
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.strategies.merger.state import StateMerger
    from pysymex._internal.typing.protocols import SolverProtocol


@dataclass(slots=True)
class ExecutorInfrastructure:
    """Infrastructure objects installed on ``SymbolicExecutor`` during construction."""

    solver: SolverProtocol
    session: ExecutionSession
    result_cache: LRUCache[str, ExecutionResult] | None
    state_merger: StateMerger | None
    resource_tracker: ResourceTracker
    cross_function: CrossFunctionAnalyzer | None
    interaction_graph: ConstraintInteractionGraph
    active_detectors: list[Detector]
    detector_dispatch: dict[str, list[Detector]]
    universal_detectors: list[Detector]


def resolve_execution_config(
    config: ExecutionConfig | None,
    config_overrides: dict[str, object],
) -> ExecutionConfig:
    """Resolve constructor config and keyword overrides without mutating caller config."""
    if config is None:
        config_ctor = cast("Callable[..., ExecutionConfig]", ExecutionConfig)
        return config_ctor(**config_overrides)
    if config_overrides:
        return replace(config, **config_overrides)
    return config


def build_executor_infrastructure(
    *,
    config: ExecutionConfig,
    detector_registry: DetectorRegistry,
    dispatcher: OpcodeDispatcher,
    state_merger_factory: Callable[..., StateMerger],
) -> ExecutorInfrastructure:
    """Build solver, session, cache, detector tables, and optional executor services."""
    from pysymex._internal.core.solver.independence.optimizer import IndependenceOptimizer

    solver = IncrementalSolver(
        timeout_ms=config.solver_timeout_ms,
        use_cache=config.enable_solver_cache,
    )
    session = ExecutionSession()
    session.reset_phase_stats()
    session.reset_last_execution_snapshots()

    cross_function = _build_cross_function(config, dispatcher)
    detector_tables = build_detector_runtime_tables(
        config=config,
        detector_registry=detector_registry,
    )
    independence_optimizer = IndependenceOptimizer()

    return ExecutorInfrastructure(
        solver=solver,
        session=session,
        result_cache=_build_result_cache(config),
        state_merger=_build_state_merger(config, state_merger_factory),
        resource_tracker=ResourceTracker(
            limits=limits_from_execution_config(config),
        ),
        cross_function=cross_function,
        interaction_graph=ConstraintInteractionGraph(independence_optimizer),
        active_detectors=detector_tables.active_detectors,
        detector_dispatch=detector_tables.detector_dispatch,
        universal_detectors=detector_tables.universal_detectors,
    )


def _build_result_cache(config: ExecutionConfig) -> LRUCache[str, ExecutionResult] | None:
    if not config.enable_caching:
        return None
    return LRUCache[str, ExecutionResult](maxsize=500)


def _build_state_merger(
    config: ExecutionConfig,
    state_merger_factory: Callable[..., StateMerger],
) -> StateMerger | None:
    if not config.enable_state_merging:
        return None
    policy_map = {
        "conservative": MergePolicy.CONSERVATIVE,
        "moderate": MergePolicy.MODERATE,
        "aggressive": MergePolicy.AGGRESSIVE,
    }
    return state_merger_factory(policy=policy_map.get(config.merge_policy, MergePolicy.MODERATE))


def _build_cross_function(
    config: ExecutionConfig,
    dispatcher: OpcodeDispatcher,
) -> CrossFunctionAnalyzer | None:
    if not config.enable_cross_function:
        return None
    cross_function = CrossFunctionAnalyzer()
    dispatcher.cross_function = cross_function
    return cross_function
