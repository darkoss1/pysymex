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

"""Path-manager protocol and heap entry wrapper for exploration scheduling.

Defines the minimal worklist API consumed by
:class:`~pysymex.execution.executors.core.SymbolicExecutor` and implemented by
:class:`~pysymex.execution.strategies.manager.path.PolarCegisPathManager`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Generic, TypeVar


T = TypeVar("T")


class ExplorationStrategy(Enum):
    """Execution-owned path-exploration strategy identifiers."""

    ADAPTIVE = "adaptive"


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
    """Heap entry ordering states by priority with deterministic tie-breaking."""

    __slots__ = ("priority", "counter", "state")

    def __init__(self, priority: float, counter: int, state: T):
        """Store one prioritized worklist entry.

        Args:
            priority: Primary sort key (larger pops first for max-heaps).
            counter: Monotonic tie-breaker so equal priorities remain stable.
            state: Opaque state identifier or payload stored in the heap.
        """
        self.priority = priority
        self.counter = counter
        self.state = state

    def __lt__(self, other: "PrioritizedState[T]") -> bool:
        """Compare for ``heapq`` max-heap ordering (higher priority sorts first)."""
        if self.priority == other.priority:
            return self.counter < other.counter
        return self.priority > other.priority
