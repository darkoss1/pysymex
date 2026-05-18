# pysymex: Python Symbolic Execution & Formal Verification
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

"""Path exploration strategies for symbolic execution."""

from __future__ import annotations

import heapq
import itertools
import math
import random
import warnings
from abc import ABC, abstractmethod
from enum import Enum
from typing import TYPE_CHECKING, Dict, Generic, List, Optional, TypeVar

from pysymex.core.graph.treewidth import ConstraintInteractionGraph
from pysymex.accel.thompson import HierarchicalThompsonScheduler, RewardMetrics

if TYPE_CHECKING:
    from pysymex.core.state import VMState

DEFAULT_RHO = 0.1
DEFAULT_LAM = 1.0
DEFAULT_TAU = 1.5
DEFAULT_GAMMA = 0.95
RANDOM_SEED = 42
TOPOLOGICAL_MULTIPLIER = 10.0
UNIFORM_PRIOR_ALPHA = 1.0
UNIFORM_PRIOR_BETA = 1.0
INFORMED_PRIOR_ALPHA = 2.0
INFORMED_PRIOR_BETA = 1.0


class ExplorationStrategy(Enum):
    """Available path-exploration strategy identifiers."""

    ADAPTIVE = "adaptive"


T = TypeVar("T")


class PathManager(ABC, Generic[T]):
    """Abstract base class for path-exploration managers."""

    @abstractmethod
    def add_state(self, state: T, priority: float = 0.0) -> None:
        """Add a state to explore."""

    @abstractmethod
    def get_next_state(self) -> T | None:
        """Get the next state to explore."""

    @abstractmethod
    def is_empty(self) -> bool:
        """Check if there are states to explore."""

    @abstractmethod
    def size(self) -> int:
        """Get number of pending states."""


class PrioritizedState(Generic[T]):
    __slots__ = ("priority", "counter", "state")

    def __init__(self, priority: float, counter: int, state: T):
        self.priority = priority
        self.counter = counter
        self.state = state

    def __lt__(self, other: "PrioritizedState[T]") -> bool:
        if self.priority == other.priority:
            return self.counter < other.counter
        return self.priority > other.priority


class TopologicalThompsonSampling:
    """
    Beta-Bernoulli multi-armed bandit with Topological Information Yield.
    Adaptive exploration strategy based on the Constraint Interaction Graph (CIG).
    """

    __slots__ = ("rho", "lam", "tau", "gamma", "arms", "last_arm", "_rng", "_total_rewards")

    def __init__(
        self,
        rho: float = DEFAULT_RHO,
        lam: float = DEFAULT_LAM,
        tau: float = DEFAULT_TAU,
        gamma: float = DEFAULT_GAMMA,
    ):
        self.rho = rho
        self.lam = lam
        self.tau = tau
        self.gamma = gamma
        self._total_rewards = 0.0

        self.arms = {
            "topological": [INFORMED_PRIOR_ALPHA, INFORMED_PRIOR_BETA],
            "coverage": [INFORMED_PRIOR_ALPHA, INFORMED_PRIOR_BETA],
            "random": [UNIFORM_PRIOR_ALPHA, UNIFORM_PRIOR_BETA],
        }
        self.last_arm: Optional[str] = None
        self._rng = random.Random(RANDOM_SEED)

    def calculate_y_topo(self, core_pcs: List[int], cig: ConstraintInteractionGraph) -> float:
        if not core_pcs:
            return 0.0

        sum_deg = sum(cig.get_degree(v) for v in core_pcs)
        core_size = len(core_pcs)

        x = self.lam * (sum_deg / (core_size**self.tau)) - self.rho
        try:
            return 1.0 / (1.0 + math.exp(-x))
        except OverflowError:
            return 0.0 if x < 0 else 1.0

    def select_arm(self) -> str:
        best_score = -1.0
        best_arm = "random"

        for arm, (alpha, beta) in self.arms.items():
            sample = self._rng.betavariate(alpha, beta)
            if sample > best_score:
                best_score = sample
                best_arm = arm

        self.last_arm = best_arm
        return best_arm

    def update_reward(self, arm: str, reward: float) -> None:
        self._total_rewards += reward
        normalized_reward = max(0.0, min(1.0, reward))
        alpha, beta = self.arms[arm]

        self.arms[arm][0] = (
            UNIFORM_PRIOR_ALPHA + self.gamma * (alpha - UNIFORM_PRIOR_ALPHA) + normalized_reward
        )
        self.arms[arm][1] = (
            UNIFORM_PRIOR_BETA
            + self.gamma * (beta - UNIFORM_PRIOR_BETA)
            + (1.0 - normalized_reward)
        )

    def reseed(self, seed: int) -> None:
        """Reseed the internal RNG for deterministic test runs."""
        self._rng.seed(seed)

    def randint(self, low: int, high: int) -> int:
        """Draw a random integer in ``[low, high]`` from the internal RNG."""
        return self._rng.randint(low, high)

    @property
    def total_rewards(self) -> float:
        """Cumulative reward mass observed across all arms."""
        return self._total_rewards


class TopologicalThompsonPathManager(PathManager["VMState"]):
    """
    Unified path manager utilizing Topological Thompson Sampling.
    """

    ARM_STRUCTURAL = "high-reuse-potential-first"
    ARM_DFS = "DFS"
    ARM_BFS = "BFS"
    ARM_COVERAGE = "coverage-guided"
    ARM_LOW_WIDTH = "low-width-first"
    ARM_SOLVER_CHEAP = "solver-cheap-first"
    ARM_RARE_BRANCH = "rare-branch-first"

    def __init__(
        self,
        cig: ConstraintInteractionGraph,
        deterministic: bool = False,
        random_seed: int = 42,
        fixed_arm: str | None = None,
    ):
        self.cig = cig
        self._rng = random.Random(random_seed)
        self.scheduler = HierarchicalThompsonScheduler(self._rng)
        self.topological_sampler = TopologicalThompsonSampling()
        self.topological_sampler.reseed(random_seed)
        self._deterministic = deterministic
        self._fixed_arm = fixed_arm
        self._states: Dict[int, "VMState"] = {}
        self._counter = itertools.count()

        # Heaps/Pools for different path policies
        self._heap_topological: List[PrioritizedState[int]] = []  # Max-priority
        self._heap_coverage: List[PrioritizedState[int]] = []  # Min-depth (BFS-like)
        self._heap_dfs: List[PrioritizedState[int]] = []  # Max-depth
        self._heap_low_width: List[PrioritizedState[int]] = []  # Min-treewidth
        self._random_pool: List[int] = []

        self._covered_pcs: set[int] = set()
        self._last_arm: str | None = None
        self._last_topological_arm: str | None = None
        self._last_decisions: dict[str, str] = {}
        self._total_rewards = 0.0

    def add_state(self, state: VMState, priority: float = 0.0) -> None:
        _ = priority
        count = next(self._counter)
        state_id = count
        pc = state.pc
        depth = state.depth
        self._states[state_id] = state

        # 1. Topological Score
        topo_score = self.cig.get_degree(pc) * TOPOLOGICAL_MULTIPLIER + depth
        heapq.heappush(self._heap_topological, PrioritizedState(topo_score, count, state_id))

        # 2. Coverage Score (BFS)
        cov_score = float(depth)
        heapq.heappush(self._heap_coverage, PrioritizedState(-cov_score, count, state_id))

        # 3. DFS Score
        dfs_score = float(depth)
        heapq.heappush(self._heap_dfs, PrioritizedState(dfs_score, count, state_id))

        # 4. Low-Width Score
        width_score = -float(self.cig.estimated_treewidth)
        heapq.heappush(self._heap_low_width, PrioritizedState(width_score, count, state_id))

        self._random_pool.append(state_id)

    def _pop_from_heap(self, heap: list[PrioritizedState[int]]) -> Optional["VMState"]:
        while heap:
            state_id = heapq.heappop(heap).state
            if state_id in self._states:
                state = self._states.pop(state_id)
                self._covered_pcs.update(state.visited_pcs)
                return state
        return None

    def _pop_random(self) -> Optional["VMState"]:
        while self._random_pool:
            idx = self._rng.randint(0, len(self._random_pool) - 1)
            self._random_pool[idx], self._random_pool[-1] = (
                self._random_pool[-1],
                self._random_pool[idx],
            )
            state_id = self._random_pool.pop()

            if state_id in self._states:
                state = self._states.pop(state_id)
                self._covered_pcs.update(state.visited_pcs)
                return state
        return None

    def get_next_state(self) -> Optional["VMState"]:
        if not self._states:
            return None

        arm = self._select_path_arm()
        self._last_arm = arm
        self._last_decisions["path"] = arm

        dispatch = {
            self.ARM_DFS: lambda: self._pop_from_heap(self._heap_dfs),
            self.ARM_BFS: lambda: self._pop_from_heap(self._heap_coverage),
            self.ARM_COVERAGE: lambda: self._pop_from_heap(self._heap_coverage),
            self.ARM_LOW_WIDTH: lambda: self._pop_from_heap(self._heap_low_width),
            self.ARM_STRUCTURAL: lambda: self._pop_from_heap(self._heap_topological),
            self.ARM_SOLVER_CHEAP: lambda: self._pop_random(),
            self.ARM_RARE_BRANCH: lambda: self._pop_from_heap(self._heap_topological),
        }

        pop_func = dispatch.get(arm, lambda: self._pop_from_heap(self._heap_topological))
        state = pop_func()

        if state is not None:
            return state

        # Fallback to any state if the chosen arm's heap was empty/stale
        for fallback_arm, fallback_func in dispatch.items():
            state = fallback_func()
            if state is not None:
                self._last_arm = fallback_arm
                self._last_decisions["path"] = fallback_arm
                return state

        return None

    def _select_path_arm(self) -> str:
        if self._fixed_arm is not None:
            return self._fixed_arm
        if self._deterministic:
            return self.ARM_STRUCTURAL
        sampled_arm = self.topological_sampler.select_arm()
        self._last_topological_arm = sampled_arm
        if sampled_arm == "coverage":
            return self.ARM_COVERAGE
        if sampled_arm == "random":
            return self.ARM_SOLVER_CHEAP
        return self.ARM_STRUCTURAL

    def update_hierarchical_reward(
        self, metrics: RewardMetrics, decisions: dict[str, str] | None = None
    ):
        """Update sampled scheduler arms from certified exploration telemetry."""
        reward = self.scheduler.compute_chtd_yield(metrics)
        self._total_rewards += reward

        all_decisions = dict(self._last_decisions)
        if decisions:
            all_decisions.update(decisions)

        for layer, arm in all_decisions.items():
            bandit = getattr(self.scheduler, layer, None)
            if bandit is not None:
                bandit.update_arm(arm, reward)
        if self._last_topological_arm is not None:
            self.topological_sampler.update_reward(self._last_topological_arm, reward)

    def is_empty(self) -> bool:
        """Check if there are states to explore."""
        return len(self._states) == 0

    def size(self) -> int:
        """Get number of pending states."""
        return len(self._states)

    def prune_states_containing_core(self, core: frozenset[int]) -> int:
        """Remove queued frontier states whose constraints contain a certified core."""
        if not core:
            return 0

        killed: list[int] = []
        for state_id, state in self._states.items():
            path_indices = {constraint.hash() for constraint in state.path_constraints}
            if core.issubset(path_indices):
                killed.append(state_id)

        for state_id in killed:
            del self._states[state_id]

        return len(killed)

    def feedback_unsat_core(
        self,
        core_pcs: List[int],
        *,
        paths_pruned: int = 0,
        elapsed_ms: float = 0.0,
        decisions: dict[str, str] | None = None,
    ) -> None:
        """EPP-based feedback for certified UNSAT-core pruning telemetry."""
        metrics = RewardMetrics(
            pruned_frontier=paths_pruned,
            centrality=sum(self.cig.get_degree(pc) for pc in core_pcs) if core_pcs else 0.0,
            core_size=len(core_pcs),
            subtree_reach=1.0,
            separator_size=0,
            core_reuse=1,
            subtree_width=self.cig.estimated_treewidth,
            solve_time_ms=elapsed_ms,
            minimize_time_ms=0.0,
        )
        self.update_hierarchical_reward(metrics, decisions)

    def feedback_mus(
        self,
        core_pcs: List[int],
        *,
        paths_pruned: int = 0,
        elapsed_ms: float = 0.0,
        decisions: dict[str, str] | None = None,
    ) -> None:
        """Deprecated alias for feedback_unsat_core."""
        warnings.warn(
            "feedback_mus is deprecated; use feedback_unsat_core instead",
            DeprecationWarning,
            stacklevel=2,
        )
        self.feedback_unsat_core(
            core_pcs,
            paths_pruned=paths_pruned,
            elapsed_ms=elapsed_ms,
            decisions=decisions,
        )

    def record_reward(self, reward: float) -> None:
        """Old API support."""
        self._total_rewards += reward
        if self._last_arm:
            self.scheduler.path.update_arm(self._last_arm, max(0.0, min(1.0, reward)))
        if self._last_topological_arm is not None:
            self.topological_sampler.update_reward(
                self._last_topological_arm,
                max(0.0, min(1.0, reward)),
            )

    def reheat_arm(self, arm_name: str, strength: float = 0.5) -> None:
        """Old API support."""
        if arm_name not in self.scheduler.path.arms:
            return
        params = self.scheduler.path.arms[arm_name]
        decay = max(0.0, min(1.0, 1.0 - strength))
        params["alpha"] *= decay
        params["beta"] *= decay

    def get_stats(self) -> dict[str, object]:
        return {
            "arms": {k: dict(v) for k, v in self.scheduler.path.arms.items()},
            "decomposition_arms": {
                k: dict(v) for k, v in self.scheduler.decomposition.arms.items()
            },
            "target_arms": {k: dict(v) for k, v in self.scheduler.target.arms.items()},
            "path_arms": {k: dict(v) for k, v in self.scheduler.path.arms.items()},
            "budget_arms": {k: dict(v) for k, v in self.scheduler.budget.arms.items()},
            "topological_arms": {k: list(v) for k, v in self.topological_sampler.arms.items()},
            "covered_pcs": len(self._covered_pcs),
            "total_rewards": self._total_rewards,
        }


AdaptivePathManager = TopologicalThompsonPathManager


def create_path_manager(
    strategy: ExplorationStrategy | str,
    cig: Optional[ConstraintInteractionGraph] = None,
    **kwargs: object,
) -> PathManager[VMState]:
    strategy_value = (
        strategy.value if isinstance(strategy, ExplorationStrategy) else strategy.lower()
    )
    if cig is None:
        from pysymex.core.solver.independence import ConstraintIndependenceOptimizer

        cig = ConstraintInteractionGraph(ConstraintIndependenceOptimizer())
    deterministic_raw = kwargs.get("deterministic", False)
    random_seed_raw = kwargs.get("random_seed", RANDOM_SEED)
    deterministic = bool(deterministic_raw)
    random_seed = random_seed_raw if isinstance(random_seed_raw, int) else RANDOM_SEED

    fixed_arm: str | None = None
    if strategy_value == "dfs":
        fixed_arm = TopologicalThompsonPathManager.ARM_DFS
    elif strategy_value == "bfs":
        fixed_arm = TopologicalThompsonPathManager.ARM_BFS
    elif strategy_value == "topological":
        fixed_arm = TopologicalThompsonPathManager.ARM_STRUCTURAL
    elif strategy_value == "random":
        fixed_arm = TopologicalThompsonPathManager.ARM_SOLVER_CHEAP

    manager = TopologicalThompsonPathManager(
        cig,
        deterministic=deterministic,
        random_seed=random_seed,
        fixed_arm=fixed_arm,
    )
    if strategy_value == "topological":
        manager.scheduler.path.arms[manager.ARM_STRUCTURAL]["alpha"] = 100.0
    elif strategy_value == "random":
        manager.scheduler.path.arms[manager.ARM_SOLVER_CHEAP]["alpha"] = 100.0

    return manager
