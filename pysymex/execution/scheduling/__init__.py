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

"""Execution path scheduling policy helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, TypeGuard

from pysymex.core.graph.cig import ConstraintInteractionGraph
from pysymex.execution.frontier import FrontierRuntimeMode
from pysymex.execution.strategies.manager.constants import RANDOM_SEED
from pysymex.execution.strategies.manager.types import ExplorationStrategy, PathManager
from pysymex.execution.strategies.merger.state import StateMerger

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState

__all__ = [
    "calculate_path_reward",
    "collect_state_merger_stats",
    "collect_worklist_stats",
    "create_path_manager",
    "FrontierRuntimeMode",
]


class _WorklistStatsProvider(Protocol):
    """Worklist interface extension for optional diagnostic stats."""

    def get_stats(self) -> dict[str, object]:
        """Return bounded diagnostic stats for the active worklist."""
        ...


def calculate_path_reward(*, new_coverage: int, new_issues: int) -> float:
    """Return the adaptive scheduler reward for one executed path step."""
    reward = 0.0
    if new_issues > 0:
        reward += 10.0 * new_issues
    if new_coverage > 0:
        reward += 3.0 * new_coverage
    elif new_coverage == 0 and new_issues == 0:
        reward -= 0.5
    return reward


def collect_state_merger_stats(state_merger: StateMerger | None) -> dict[str, object]:
    """Return fixed-schema state-merger statistics for execution results."""
    if state_merger is None:
        return {
            "enabled": False,
            "states_before_merge": 0,
            "states_after_merge": 0,
            "merge_operations": 0,
            "subsumption_hits": 0,
            "reduction_ratio": 0.0,
        }
    stats = state_merger.stats
    return {
        "enabled": True,
        "states_before_merge": stats.states_before_merge,
        "states_after_merge": stats.states_after_merge,
        "merge_operations": stats.merge_operations,
        "subsumption_hits": stats.subsumption_hits,
        "reduction_ratio": stats.reduction_ratio,
    }


def collect_worklist_stats(worklist: PathManager["VMState"] | None) -> dict[str, object]:
    """Return fixed-schema worklist diagnostics for execution results."""
    if worklist is None:
        return {
            "enabled": False,
            "pending_states": 0,
        }
    stats: dict[str, object] = {
        "enabled": True,
        "pending_states": worklist.size(),
    }
    if _is_worklist_stats_provider(worklist):
        stats.update(worklist.get_stats())
    return stats


def create_path_manager(
    strategy: ExplorationStrategy,
    cig: ConstraintInteractionGraph | None = None,
    frontier_runtime_mode: FrontierRuntimeMode = FrontierRuntimeMode.POLAR_CEGIS_RUNTIME,
    **kwargs: object,
) -> PathManager[VMState]:
    """Construct the adaptive path manager for symbolic exploration."""
    if strategy is not ExplorationStrategy.ADAPTIVE:
        msg = f"unsupported exploration strategy: {strategy!r}"
        raise ValueError(msg)
    if cig is None:
        from pysymex.core.solver.independence.optimizer import ConstraintIndependenceOptimizer

        cig = ConstraintInteractionGraph(ConstraintIndependenceOptimizer())
    from pysymex.execution.strategies.manager.path import PolarCegisPathManager

    deterministic_raw = kwargs.get("deterministic", False)
    random_seed_raw = kwargs.get("random_seed", RANDOM_SEED)
    deterministic = bool(deterministic_raw)
    random_seed = random_seed_raw if isinstance(random_seed_raw, int) else RANDOM_SEED

    return PolarCegisPathManager(
        cig,
        deterministic=deterministic,
        random_seed=random_seed,
        frontier_runtime_mode=frontier_runtime_mode,
    )


def _is_worklist_stats_provider(value: object) -> TypeGuard[_WorklistStatsProvider]:
    """Return whether ``value`` exposes bounded worklist diagnostics."""
    get_stats = getattr(value, "get_stats", None)
    return callable(get_stats)
