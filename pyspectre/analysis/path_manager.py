"""Path exploration strategies for symbolic execution."""

from __future__ import annotations
import heapq
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyspectre.core.state import VMState


class ExplorationStrategy(Enum):
    """Path exploration strategies."""

    DFS = auto()
    BFS = auto()
    RANDOM = auto()
    COVERAGE = auto()
    DIRECTED = auto()
    HYBRID = auto()


@dataclass(order=True)
class PrioritizedState:
    """State with priority for exploration."""

    priority: float
    state: VMState = field(compare=False)

    @classmethod
    def from_state(cls, state: VMState, priority: float = 0.0) -> PrioritizedState:
        return cls(priority=priority, state=state)


class PathManager(ABC):
    """Abstract base class for path exploration managers."""

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
    """Coverage-guided path exploration."""

    def __init__(self):
        self._heap: list[PrioritizedState] = []
        self._covered_pcs: set[int] = set()
        self._covered_branches: set[tuple[int, bool]] = set()

    def add_state(self, state: VMState, priority: float = 0.0) -> None:
        new_pcs = len(state.visited_pcs - self._covered_pcs)
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
    """Target-directed path exploration."""

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
    """Hybrid path exploration combining multiple strategies."""

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
            return self._dfs.get_next_state()
        elif choice < self._weights["dfs"] + self._weights["coverage"]:
            return self._coverage.get_next_state()
        else:
            if self._all_states:
                idx = self._random.randint(0, len(self._all_states) - 1)
                return self._all_states.pop(idx)
            return None

    def is_empty(self) -> bool:
        return self._dfs.is_empty() and self._coverage.is_empty() and not self._all_states

    def size(self) -> int:
        return max(self._dfs.size(), self._coverage.size(), len(self._all_states))


def create_path_manager(strategy: ExplorationStrategy, **kwargs) -> PathManager:
    """Factory function for path managers."""
    if strategy == ExplorationStrategy.DFS:
        return DFSPathManager()
    elif strategy == ExplorationStrategy.BFS:
        return BFSPathManager()
    elif strategy == ExplorationStrategy.COVERAGE:
        return CoverageGuidedPathManager()
    elif strategy == ExplorationStrategy.DIRECTED:
        targets = kwargs.get("targets", set())
        return DirectedPathManager(targets)
    elif strategy == ExplorationStrategy.HYBRID:
        return HybridPathManager(**kwargs)
    else:
        return DFSPathManager()
