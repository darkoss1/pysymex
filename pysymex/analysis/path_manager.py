"""Path exploration strategies for symbolic execution.

Provides pluggable managers (DFS, BFS, coverage-guided, directed,
adaptive) that determine the order in which states are explored.
"""

from __future__ import annotations

import collections
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

    DFS = auto()
    BFS = auto()
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


class DFSPathManager(PathManager[T]):
    """Depth-first search path exploration."""

    def __init__(self):
        self._stack: list[T] = []

    def add_state(self, state: T, priority: float = 0.0) -> None:
        self._stack.append(state)

    def get_next_state(self) -> T | None:
        """Get next state."""
        if self._stack:
            return self._stack.pop()
        return None

    def is_empty(self) -> bool:
        return len(self._stack) == 0

    def size(self) -> int:
        return len(self._stack)


class BFSPathManager(PathManager[T]):
    """Breadth-first search path exploration."""

    def __init__(self):
        self._queue: collections.deque[T] = collections.deque()

    def add_state(self, state: T, priority: float = 0.0) -> None:
        self._queue.append(state)

    def get_next_state(self) -> T | None:
        """Get next state."""
        if self._queue:
            return self._queue.popleft()
        return None

    def is_empty(self) -> bool:
        return len(self._queue) == 0

    def size(self) -> int:
        return len(self._queue)


@dataclass(frozen=True, order=True)
class PrioritizedState(Generic[T]):
    """Priority-wrapped item for heap-based scheduling."""

    priority: float
    state: T = field(compare=False)


class PriorityPathManager(PathManager[T]):
    """Priority-based path exploration (for coverage/directed)."""

    def __init__(self):
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

    def __init__(self):
        self._heap: list[PrioritizedState["VMState"]] = []
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


class DirectedPathManager(PathManager["VMState"]):
    """Target-directed path exploration prioritising states near target PCs.

    Args:
        targets: Set of target program counters to aim for.
    """

    def __init__(self, targets: set[int]):
        self._heap: list[PrioritizedState["VMState"]] = []
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

    Maintains three sub-strategies (DFS, coverage-guided, random) and
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
    arithmetic bugs reward DFS differently than web frameworks with
    taint-flow vulnerabilities. The discounted variant achieves robust
    bounds under non-stationary bandit theory.

    Attributes:
        _arms: Per-strategy Beta priors (alpha, beta).
        _gamma: Discount factor for non-stationarity (default 0.95).
        _covered_pcs: Global set of covered program counters.
        _last_arm: Which arm was selected for the most recent state.
        _total_rewards: Cumulative reward signal for diagnostics.
    """

    # Arm names correspond to sub-strategies
    ARM_DFS = "dfs"
    ARM_COVERAGE = "coverage"
    ARM_RANDOM = "random"

    # Reward normalization bounds (raw rewards mapped to [0, 1])
    _REWARD_MIN = -5.0
    _REWARD_MAX = 10.0

    def __init__(
        self,
        dfs_prior: tuple[float, float] = (2.0, 1.0),
        coverage_prior: tuple[float, float] = (2.0, 1.0),
        random_prior: tuple[float, float] = (1.0, 1.0),
        gamma: float = 0.95,
    ):
        self._entry_counter = itertools.count()
        self.store: dict[int, VMState] = {}
        self._dfs: list[int] = []  # stack of entry IDs (LIFO)
        self._coverage_heap: list[PrioritizedState[int]] = []  # heap of (priority, eid)
        self._random_pool: list[int] = []  # list of entry IDs

        # Beta(alpha, beta) priors for each arm
        self._arms: dict[str, list[float]] = {
            self.ARM_DFS: list(dfs_prior),
            self.ARM_COVERAGE: list(coverage_prior),
            self.ARM_RANDOM: list(random_prior),
        }

        self._covered_pcs: set[int] = set()
        self._returned_ids: set[int] = set()
        self._total_entries = 0
        self._last_arm: str | None = None
        self._total_rewards: float = 0.0
        self._arm_selections: dict[str, int] = {a: 0 for a in self._arms}
        self._gamma = gamma

    def add_state(self, state: VMState, priority: float = 0.0) -> None:
        eid = next(self._entry_counter)
        self.store[eid] = state
        self._dfs.append(eid)

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

        # Normalize reward to [0, 1] for conjugate prior validity
        clamped = max(self._REWARD_MIN, min(self._REWARD_MAX, reward))
        r = (clamped - self._REWARD_MIN) / (self._REWARD_MAX - self._REWARD_MIN)

        # Discounted update: decay prior then add observation
        arm = self._arms[self._last_arm]
        arm[0] = self._gamma * arm[0] + r
        arm[1] = self._gamma * arm[1] + (1.0 - r)

        self._total_rewards += reward

    def _thompson_sample(self) -> str:
        """Select an arm via Thompson Sampling (Beta-Bernoulli)."""
        best_arm = self.ARM_DFS
        best_sample = -1.0
        for arm_name, (alpha, beta) in self._arms.items():
            # Clamp to epsilon: betavariate requires strictly positive params.
            # After many gamma-discounted updates the losing arm's beta (or
            # alpha) can decay toward 0 via float underflow, causing ValueError.
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

    def _pop_unique_from_heap(self) -> VMState | None:
        while self._coverage_heap:
            ps = heapq.heappop(self._coverage_heap)
            eid = ps.state  # PrioritizedState.state is an entry ID here
            if eid not in self._returned_ids:
                self._returned_ids.add(eid)
                state = self.store.pop(eid)
                self._covered_pcs.update(state.visited_pcs)
                return state
        return None

    def _pop_unique_random(self) -> VMState | None:
        while self._random_pool:
            idx = _random_mod.randint(0, len(self._random_pool) - 1)
            eid = self._random_pool.pop(idx)
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
            self.ARM_DFS: lambda: self._pop_unique_from_stack(self._dfs),
            self.ARM_COVERAGE: self._pop_unique_from_heap,
            self.ARM_RANDOM: self._pop_unique_random,
        }

        state = dispatch[arm]()
        if state is not None:
            return state

        # Fallback through other arms
        for fallback_arm in [self.ARM_DFS, self.ARM_COVERAGE, self.ARM_RANDOM]:
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
) -> PathManager["VMState"]:
    """Factory function for creating a path manager from a strategy enum.

    Args:
        strategy: The exploration strategy to use.
        **kwargs: Extra arguments forwarded to the chosen manager.

    Returns:
        A concrete ``PathManager`` instance.
    """
    if strategy == ExplorationStrategy.DFS:
        return DFSPathManager()
    elif strategy == ExplorationStrategy.BFS:
        return BFSPathManager()
    elif strategy == ExplorationStrategy.COVERAGE:
        return CoverageGuidedPathManager()
    elif strategy == ExplorationStrategy.DIRECTED:
        targets: set[int] = kwargs.get("targets", set())  # type: ignore[assignment]
        return DirectedPathManager(targets)
    elif strategy == ExplorationStrategy.ADAPTIVE:
        return AdaptivePathManager(**kwargs)  # type: ignore[arg-type]
    else:
        return DFSPathManager()
