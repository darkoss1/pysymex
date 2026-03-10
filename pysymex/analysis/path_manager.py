"""Path exploration strategies for symbolic execution.

Provides pluggable managers (DFS, BFS, coverage-guided, directed,
hybrid) that determine the order in which states are explored.
"""

from __future__ import annotations

import heapq
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.core.state import VMState


class ExplorationStrategy(Enum):
    """Available path-exploration strategy identifiers."""

    DFS = auto()
    BFS = auto()
    RANDOM = auto()
    COVERAGE = auto()
    DIRECTED = auto()
    HYBRID = auto()


@dataclass(frozen=True, slots=True, order=True)
class PrioritizedState:
    """VM state paired with a numeric priority for heap-based scheduling.

    Attributes:
        priority: Lower values are dequeued first.
        state: The ``VMState`` to explore.
    """

    priority: float
    state: VMState = field(compare=False)

    @classmethod
    def from_state(cls, state: VMState, priority: float = 0.0) -> PrioritizedState:
        return cls(priority=priority, state=state)


class PathManager(ABC):
    """Abstract base class for path-exploration managers.

    Implementations define how states are queued, dequeued, and prioritised.
    """

    @abstractmethod
    def add_state(self, state: VMState, priority: float = 0.0) -> None:
        """Add a state to explore."""

    @abstractmethod
    def get_next_state(self) -> VMState | None:
        """Get the next state to explore."""

    @abstractmethod
    def is_empty(self) -> bool:
        """Check if there are states to explore."""

    @abstractmethod
    def size(self) -> int:
        """Get number of pending states."""


class DFSPathManager(PathManager):
    """Depth-first search path exploration."""

    def __init__(self):
        self._stack: list[VMState] = []

    def add_state(self, state: VMState, priority: float = 0.0) -> None:
        self._stack.append(state)

    def get_next_state(self) -> VMState | None:
        if self._stack:
            return self._stack.pop()
        return None

    def is_empty(self) -> bool:
        return len(self._stack) == 0

    def size(self) -> int:
        return len(self._stack)


class BFSPathManager(PathManager):
    """Breadth-first search path exploration."""

    def __init__(self):
        self._queue: list[VMState] = []

    def add_state(self, state: VMState, priority: float = 0.0) -> None:
        self._queue.append(state)

    def get_next_state(self) -> VMState | None:
        if self._queue:
            return self._queue.pop(0)
        return None

    def is_empty(self) -> bool:
        return len(self._queue) == 0

    def size(self) -> int:
        return len(self._queue)


class PriorityPathManager(PathManager):
    """Priority-based path exploration (for coverage/directed)."""

    def __init__(self):
        self._heap: list[PrioritizedState] = []

    def add_state(self, state: VMState, priority: float = 0.0) -> None:
        heapq.heappush(self._heap, PrioritizedState(priority, state))

    def get_next_state(self) -> VMState | None:
        if self._heap:
            return heapq.heappop(self._heap).state
        return None

    def is_empty(self) -> bool:
        return len(self._heap) == 0

    def size(self) -> int:
        return len(self._heap)


class CoverageGuidedPathManager(PathManager):
    """Coverage-guided exploration prioritising states that cover new PCs.

    Attributes:
        _covered_pcs: Set of already-covered program counters.
        _covered_branches: Set of already-covered branch outcomes.
    """

    def __init__(self):
        self._heap: list[PrioritizedState] = []
        self._covered_pcs: set[int] = set()
        self._covered_branches: set[tuple[int, bool]] = set()

    def add_state(self, state: VMState, priority: float = 0.0) -> None:
        new_pcs = len(set(state.visited_pcs) - self._covered_pcs)
        adjusted_priority = -new_pcs
        heapq.heappush(self._heap, PrioritizedState(adjusted_priority, state))

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

    def get_coverage(self) -> tuple[int, set[int]]:
        """Get coverage statistics."""
        return len(self._covered_pcs), self._covered_pcs


class DirectedPathManager(PathManager):
    """Target-directed path exploration prioritising states near target PCs.

    Args:
        targets: Set of target program counters to aim for.
    """

    def __init__(self, targets: set[int]):
        self._heap: list[PrioritizedState] = []
        self._targets = targets

    def add_state(self, state: VMState, priority: float = 0.0) -> None:
        distance = self._estimate_distance(state)
        heapq.heappush(self._heap, PrioritizedState(distance, state))

    def _estimate_distance(self, state: VMState) -> float:
        """Estimate distance to nearest target."""
        if not self._targets:
            return 0.0
        min_dist = min(abs(state.pc - target) for target in self._targets)
        return float(min_dist)

    def get_next_state(self) -> VMState | None:
        if self._heap:
            return heapq.heappop(self._heap).state
        return None

    def is_empty(self) -> bool:
        return len(self._heap) == 0

    def size(self) -> int:
        return len(self._heap)


class HybridPathManager(PathManager):
    """Hybrid path exploration combining DFS, coverage, and random sampling.

    Args:
        dfs_weight: Probability of choosing DFS next.
        coverage_weight: Probability of choosing coverage-guided next.
        random_weight: Probability of choosing a random state.
    """

    def __init__(
        self,
        dfs_weight: float = 0.5,
        coverage_weight: float = 0.3,
        random_weight: float = 0.2,
    ):
        import random

        self._random = random
        self._dfs = DFSPathManager()
        self._coverage = CoverageGuidedPathManager()
        self._weights = {
            "dfs": dfs_weight,
            "coverage": coverage_weight,
            "random": random_weight,
        }
        self._all_states: list[VMState] = []

    def add_state(self, state: VMState, priority: float = 0.0) -> None:
        self._dfs.add_state(state)
        self._coverage.add_state(state)
        self._all_states.append(state)

    def get_next_state(self) -> VMState | None:
        if self.is_empty():
            return None
        choice = self._random.random()
        if choice < self._weights["dfs"]:
            state = self._dfs.get_next_state()
            if state is not None:
                return state
        elif choice < self._weights["dfs"] + self._weights["coverage"]:
            state = self._coverage.get_next_state()
            if state is not None:
                return state
        else:
            if self._all_states:
                idx = self._random.randint(0, len(self._all_states) - 1)
                return self._all_states.pop(idx)

        if not self._dfs.is_empty():
            return self._dfs.get_next_state()
        if not self._coverage.is_empty():
            return self._coverage.get_next_state()
        if self._all_states:
            return self._all_states.pop()
        return None

    def is_empty(self) -> bool:
        return self._dfs.is_empty() and self._coverage.is_empty() and not self._all_states

    def size(self) -> int:
        return len(self._all_states)


def create_path_manager(strategy: ExplorationStrategy, **kwargs: object) -> PathManager:
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
        targets: set[int] = kwargs.get("targets", set())
        return DirectedPathManager(targets)
    elif strategy == ExplorationStrategy.HYBRID:
        return HybridPathManager(**kwargs)
    else:
        return DFSPathManager()
