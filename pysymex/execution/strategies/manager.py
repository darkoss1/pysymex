# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Path exploration strategies for symbolic execution.

Provides pluggable managers (CHTD-native, coverage-guided, directed,
adaptive) that determine the order in which states are explored.
"""

from __future__ import annotations

import heapq
import itertools
import random as _random_mod
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Generic, TypeVar

if TYPE_CHECKING:
    from pysymex.core.state import VMState


class ExplorationStrategy(Enum):
    """Available path-exploration strategy identifiers."""

    CHTD_NATIVE = auto()
    RANDOM = auto()
    COVERAGE = auto()
    DIRECTED = auto()
    ADAPTIVE = auto()


T = TypeVar("T")


class PathManager(ABC, Generic[T]):
    """Abstract base class for path-exploration managers.

    Implementations define how states are queued, dequeued, and prioritised.
    """

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


@dataclass(frozen=True, order=True)
class PrioritizedState(Generic[T]):
    """Priority-wrapped item for heap-based scheduling."""

    priority: float
    state: T = field(compare=False)


class PriorityPathManager(PathManager[T]):
    """Priority-based path exploration (for coverage/directed)."""

    def __init__(self) -> None:
        self._heap: list[PrioritizedState[T]] = []

    def add_state(self, state: T, priority: float = 0.0) -> None:
        heapq.heappush(self._heap, PrioritizedState(priority, state))

    def get_next_state(self) -> T | None:
        """Get next state."""
        if self._heap:
            return heapq.heappop(self._heap).state
        return None

    def is_empty(self) -> bool:
        return len(self._heap) == 0

    def size(self) -> int:
        return len(self._heap)


class CoverageGuidedPathManager(PathManager["VMState"]):
    """Coverage-guided exploration prioritising states that cover new PCs.

    Attributes:
        _covered_pcs: Set of already-covered program counters.
        _covered_branches: Set of already-covered branch outcomes.
    """

    def __init__(self) -> None:
        self._heap: list[PrioritizedState[VMState]] = []
        self._covered_pcs: set[int] = set()
        self._covered_branches: set[tuple[int, bool]] = set()

    def add_state(self, state: VMState, priority: float = 0.0) -> None:
        """Add state."""
        new_pcs = len(set(state.visited_pcs) - self._covered_pcs)
        adjusted_priority = -new_pcs
        heapq.heappush(self._heap, PrioritizedState(adjusted_priority, state))

    def get_next_state(self) -> VMState | None:
        """Get next state."""
        if self._heap:
            state = heapq.heappop(self._heap).state
            self._covered_pcs.update(state.visited_pcs)
            return state
        return None

    def is_empty(self) -> bool:
        return len(self._heap) == 0

    def size(self) -> int:
        return len(self._heap)

    def get_coverage(self) -> tuple[int, set[int]]:
        """Get coverage statistics."""
        return len(self._covered_pcs), self._covered_pcs


class CHTDNativePathManager(PathManager["VMState"]):
    """CHTD-first scheduler prioritizing states that enrich structural pruning.

    Score favors states that quickly expand/stabilize the interaction graph:
    - more pending constraints
    - longer path constraints
    - deeper branch histories
    - discovery of uncovered PCs
    """

    def __init__(self) -> None:
        self._heap: list[PrioritizedState[VMState]] = []
        self._covered_pcs: set[int] = set()

    def _priority(self, state: VMState) -> float:
        new_pcs = len(set(state.visited_pcs) - self._covered_pcs)
        structural = (
            (new_pcs * 100)
            + (state.pending_constraint_count * 12)
            + min(len(state.path_constraints), 128)
            + min(state.depth, 256)
        )

        return float(-structural)

    def add_state(self, state: VMState, priority: float = 0.0) -> None:
        heapq.heappush(self._heap, PrioritizedState(self._priority(state), state))

    def get_next_state(self) -> VMState | None:
        if self._heap:
            state = heapq.heappop(self._heap).state
            self._covered_pcs.update(state.visited_pcs)
            return state
        return None

    def is_empty(self) -> bool:
        return len(self._heap) == 0

    def size(self) -> int:
        return len(self._heap)


class DirectedPathManager(PathManager["VMState"]):
    """Target-directed path exploration prioritising states near target PCs.

    Args:
        targets: Set of target program counters to aim for.
    """

    def __init__(self, targets: set[int]) -> None:
        self._heap: list[PrioritizedState[VMState]] = []
        self._targets = targets

    def add_state(self, state: VMState, priority: float = 0.0) -> None:
        """Add state."""
        distance = self._estimate_distance(state)
        heapq.heappush(self._heap, PrioritizedState(distance, state))

    def _estimate_distance(self, state: VMState) -> float:
        """Estimate distance to nearest target."""
        if not self._targets:
            return 0.0
        min_dist = min(abs(state.pc - target) for target in self._targets)
        return float(min_dist)

    def get_next_state(self) -> VMState | None:
        """Get next state."""
        if self._heap:
            return heapq.heappop(self._heap).state
        return None

    def is_empty(self) -> bool:
        return len(self._heap) == 0

    def size(self) -> int:
        return len(self._heap)


class AdaptivePathManager(PathManager["VMState"]):
    """Multi-armed bandit path manager using Discounted Thompson Sampling.

    Maintains three sub-strategies (CHTD-structural, coverage-guided, random) and
    uses a conjugate Beta-Bernoulli model per arm to balance
    exploration vs. exploitation.  The reward signal is based on
    whether following a strategy leads to new coverage or issue
    discovery.

    To handle the highly non-stationary environment of symbolic execution
    (where "coverage" rewards naturally dry up over time), a discount
    factor γ ∈ (0, 1) is applied to gradually forget outdated successes.
    Rewards are normalized to [0, 1] to maintain strict Bayesian conjugate
    prior validity.

    Thompson Sampling has O(sqrt(T log T)) regret and naturally
    adapts to the project's bug-distribution: projects with many
    arithmetic bugs reward structural prioritization differently than web frameworks with
    taint-flow vulnerabilities. The discounted variant achieves robust
    bounds under non-stationary bandit theory.

    Attributes:
        _arms: Per-strategy Beta priors (alpha, beta).
        _gamma: Discount factor for non-stationarity (default 0.95).
        _covered_pcs: Global set of covered program counters.
        _last_arm: Which arm was selected for the most recent state.
        _total_rewards: Cumulative reward signal for diagnostics.
    """

    ARM_STRUCTURAL = "structural"
    ARM_COVERAGE = "coverage"
    ARM_RANDOM = "random"

    _REWARD_MIN = -5.0
    _REWARD_MAX = 10.0

    def __init__(
        self,
        structural_prior: tuple[float, float] = (2.0, 1.0),
        coverage_prior: tuple[float, float] = (2.0, 1.0),
        random_prior: tuple[float, float] = (1.0, 1.0),
        gamma: float = 0.95,
        prior_mix: float = 0.05,
        deterministic: bool = False,
        random_seed: int = 42,
    ) -> None:
        self._entry_counter = itertools.count()
        self.store: dict[int, VMState] = {}
        self._structural_heap: list[PrioritizedState[int]] = []
        self._coverage_heap: list[PrioritizedState[int]] = []
        self._random_pool: list[int] = []

        self._arm_priors: dict[str, tuple[float, float]] = {
            self.ARM_STRUCTURAL: structural_prior,
            self.ARM_COVERAGE: coverage_prior,
            self.ARM_RANDOM: random_prior,
        }
        self._arms: dict[str, list[float]] = {
            arm_name: [alpha, beta]
            for arm_name, (alpha, beta) in self._arm_priors.items()
        }

        self._covered_pcs: set[int] = set()
        self._returned_ids: set[int] = set()
        self._total_entries = 0
        self._last_arm: str | None = None
        self._total_rewards: float = 0.0
        self._arm_selections: dict[str, int] = dict.fromkeys(self._arms, 0)
        self._gamma = gamma
        self._prior_mix = prior_mix
        self._deterministic = deterministic
        self._rng = _random_mod.Random(random_seed)

    def _structural_priority(self, state: VMState) -> float:
        new_pcs = len(set(state.visited_pcs) - self._covered_pcs)
        structural = (
            (new_pcs * 100)
            + (state.pending_constraint_count * 12)
            + min(len(state.path_constraints), 128)
            + min(state.depth, 256)
        )
        return float(-structural)

    def add_state(self, state: VMState, priority: float = 0.0) -> None:
        eid = next(self._entry_counter)
        self.store[eid] = state
        heapq.heappush(
            self._structural_heap, PrioritizedState(self._structural_priority(state), eid)
        )

        new_pcs = len(set(state.visited_pcs) - self._covered_pcs)
        heapq.heappush(self._coverage_heap, PrioritizedState(-new_pcs, eid))

        self._random_pool.append(eid)
        self._total_entries += 1

    def record_reward(self, reward: float) -> None:
        """Feed a reward signal back to update the last-selected arm.

        Uses Discounted Thompson Sampling: rewards are normalized to [0, 1]
        to maintain strict Bayesian conjugate prior validity, and a discount
        factor γ is applied to gradually forget outdated successes for
        non-stationary environments.

        Update rule:
            α_k ← γ·α_k + r
            β_k ← γ·β_k + (1 - r)

        Call this after the executor processes the state returned by
        ``get_next_state()``.  Typical reward signals:

        - +10.0 for discovering a new issue (HIGH severity)
        - +3.0  for covering a new basic block
        - +1.0  for covering a new branch
        - -1.0  for hitting a resource limit
        - -5.0  for immediate UNSAT (infeasible path)
        """
        if self._last_arm is None:
            return
        if self._deterministic:
            return

        clamped = max(self._REWARD_MIN, min(self._REWARD_MAX, reward))
        r = (clamped - self._REWARD_MIN) / (self._REWARD_MAX - self._REWARD_MIN)

        arm_name = self._last_arm
        arm = self._arms[arm_name]
        prior_alpha, prior_beta = self._arm_priors[arm_name]
        arm[0] = self._gamma * arm[0] + r + (1.0 - self._gamma) * self._prior_mix * prior_alpha
        arm[1] = (
            self._gamma * arm[1]
            + (1.0 - r)
            + (1.0 - self._gamma) * self._prior_mix * prior_beta
        )

        self._total_rewards += reward

    def reheat_arm(self, arm_name: str, strength: float = 0.5) -> None:
        """Blend an arm back toward its prior to recover from stale posteriors."""
        if arm_name not in self._arms:
            return
        strength = max(0.0, min(1.0, strength))
        prior_alpha, prior_beta = self._arm_priors[arm_name]
        arm = self._arms[arm_name]
        arm[0] = ((1.0 - strength) * arm[0]) + (strength * prior_alpha)
        arm[1] = ((1.0 - strength) * arm[1]) + (strength * prior_beta)

    def _thompson_sample(self) -> str:
        """Select an arm via Thompson Sampling (Beta-Bernoulli)."""
        if self._deterministic:
            arm_order = [self.ARM_STRUCTURAL, self.ARM_COVERAGE, self.ARM_RANDOM]
            best_arm = self.ARM_STRUCTURAL
            best_score = -1.0
            for arm_name in arm_order:
                alpha, beta = self._arms[arm_name]
                score = alpha / max(alpha + beta, 1e-10)
                if score > best_score:
                    best_score = score
                    best_arm = arm_name
            return best_arm

        best_arm = self.ARM_STRUCTURAL
        best_sample = -1.0
        for arm_name, (alpha, beta) in self._arms.items():
            sample = _random_mod.betavariate(max(alpha, 1e-10), max(beta, 1e-10))
            if sample > best_sample:
                best_sample = sample
                best_arm = arm_name
        return best_arm

    def _pop_unique_from_stack(self, stack: list[int]) -> VMState | None:
        while stack:
            eid = stack.pop()
            if eid not in self._returned_ids:
                self._returned_ids.add(eid)
                state = self.store.pop(eid)
                self._covered_pcs.update(state.visited_pcs)
                return state
        return None

    def _pop_unique_from_structural_heap(self) -> VMState | None:
        while self._structural_heap:
            ps = heapq.heappop(self._structural_heap)
            eid = ps.state
            if eid not in self._returned_ids:
                self._returned_ids.add(eid)
                state = self.store.pop(eid)
                self._covered_pcs.update(state.visited_pcs)
                return state
        return None

    def _pop_unique_from_heap(self) -> VMState | None:
        while self._coverage_heap:
            ps = heapq.heappop(self._coverage_heap)
            eid = ps.state
            if eid not in self._returned_ids:
                self._returned_ids.add(eid)
                state = self.store.pop(eid)
                self._covered_pcs.update(state.visited_pcs)
                return state
        return None

    def _pop_unique_random(self) -> VMState | None:
        while self._random_pool:
            idx = self._rng.randint(0, len(self._random_pool) - 1)
            eid = self._random_pool[idx]
            last_idx = len(self._random_pool) - 1
            self._random_pool[idx] = self._random_pool[last_idx]
            self._random_pool.pop()
            if eid not in self._returned_ids:
                self._returned_ids.add(eid)
                state = self.store.pop(eid)
                self._covered_pcs.update(state.visited_pcs)
                return state
        return None

    def get_next_state(self) -> VMState | None:
        if self.is_empty():
            return None

        arm = self._thompson_sample()
        self._last_arm = arm
        self._arm_selections[arm] += 1

        dispatch = {
            self.ARM_STRUCTURAL: self._pop_unique_from_structural_heap,
            self.ARM_COVERAGE: self._pop_unique_from_heap,
            self.ARM_RANDOM: self._pop_unique_random,
        }

        state = dispatch[arm]()
        if state is not None:
            return state

        for fallback_arm in [self.ARM_STRUCTURAL, self.ARM_COVERAGE, self.ARM_RANDOM]:
            if fallback_arm != arm:
                state = dispatch[fallback_arm]()
                if state is not None:
                    self._last_arm = fallback_arm
                    return state
        return None

    def is_empty(self) -> bool:
        return len(self._returned_ids) >= self._total_entries

    def size(self) -> int:
        return self._total_entries - len(self._returned_ids)

    def get_stats(self) -> dict[str, object]:
        """Diagnostic statistics for the bandit."""
        return {
            "arms": {k: {"alpha": v[0], "beta": v[1]} for k, v in self._arms.items()},
            "selections": dict(self._arm_selections),
            "total_rewards": self._total_rewards,
            "covered_pcs": len(self._covered_pcs),
        }


def create_path_manager(  # type: ignore[return]
    strategy: ExplorationStrategy,
    **kwargs: object,
) -> PathManager[VMState]:
    """Create the runtime path manager.

    Args:
        strategy: Requested strategy (retained for API compatibility).
        **kwargs: Extra arguments forwarded to the adaptive manager.

    Returns:
        A concrete ``PathManager`` instance.

    Notes:
        Runtime execution now standardizes on discounted Thompson Sampling
        for codebase-wide CHTD-TS behavior. The ``strategy`` argument is
        accepted for backward compatibility but no longer changes runtime
        scheduler selection.
    """
    _ = strategy
    return AdaptivePathManager(**kwargs)  # type: ignore[arg-type]
