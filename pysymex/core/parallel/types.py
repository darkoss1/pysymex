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

"""Parallel path exploration types for pysymex.

Dataclasses, enums, and type-only definitions used by the parallel
exploration engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Generic,
    TypeVar,
)


class ExplorationStrategy(Enum):
    """Path exploration strategies."""

    ADAPTIVE = auto()
    CHTD_NATIVE = auto()
    RANDOM = auto()
    COVERAGE = auto()
    PRIORITY = auto()


@dataclass
class ExplorationConfig:
    """Configuration for parallel exploration."""

    max_workers: int = 4
    strategy: ExplorationStrategy = ExplorationStrategy.ADAPTIVE
    max_paths_per_worker: int = 250
    sync_interval_ms: int = 100
    enable_state_merging: bool = True
    merge_threshold: int = 10
    timeout_seconds: float = 60.0
    max_queue_size: int = 0


T = TypeVar("T")


@dataclass
class WorkItem(Generic[T]):
    """A unit of work for parallel exploration."""

    state: T
    priority: float = 0.0
    depth: int = 0
    path_id: int = 0
    parent_id: int | None = None

    def __lt__(self, other: WorkItem[T]) -> bool:
        """Compare by priority for heap operations."""
        return self.priority > other.priority


@dataclass(frozen=True, slots=True)
class PathResult:
    """Result from exploring a single path."""

    path_id: int
    status: str
    issues: list[dict[str, object]] = field(default_factory=lambda: list[dict[str, object]]())
    coverage: set[int] = field(default_factory=lambda: set[int]())
    constraints_count: int = 0
    time_seconds: float = 0.0
    error: str | None = None


@dataclass
class ExplorationResult:
    """Aggregated result from parallel exploration."""

    total_paths: int = 0
    completed_paths: int = 0
    issues: list[dict[str, object]] = field(default_factory=lambda: list[dict[str, object]]())
    coverage: set[int] = field(default_factory=lambda: set[int]())
    time_seconds: float = 0.0
    workers_used: int = 0
    paths_per_worker: dict[int, int] = field(default_factory=lambda: dict[int, int]())
    cache_hits: int = 0
    states_merged: int = 0
    timeouts: int = 0
    errors: int = 0

    def add_path_result(self, result: PathResult, worker_id: int) -> None:
        """Add a path result to the aggregate."""
        self.total_paths += 1
        if result.status == "completed":
            self.completed_paths += 1
        elif result.status == "timeout":
            self.timeouts += 1
        elif result.status == "error":
            self.errors += 1
        self.issues.extend(result.issues)
        self.coverage.update(result.coverage)
        self.paths_per_worker[worker_id] = self.paths_per_worker.get(worker_id, 0) + 1


@dataclass
class StateSignature:
    """Signature for identifying similar states for merging."""

    pc: int
    stack_depth: int
    local_keys: frozenset[str]
    constraint_hash: int
    constraint_discriminator: tuple[int, ...] = ()

    def __hash__(self) -> int:
        """Compute a hash for the signature, incorporating all structural components.

        The discriminator is included to ensure that hash collisions in the
        structural_hash do not lead to incorrect state merges.
        """
        return hash(
            (
                self.pc,
                self.stack_depth,
                self.local_keys,
                self.constraint_hash,
                self.constraint_discriminator,
            )
        )

    def __eq__(self, other: object) -> bool:
        """Perform full structural equality check between two state signatures."""

        if not isinstance(other, StateSignature):
            return False
        return (
            self.pc == other.pc
            and self.stack_depth == other.stack_depth
            and self.local_keys == other.local_keys
            and self.constraint_hash == other.constraint_hash
            and self.constraint_discriminator == other.constraint_discriminator
        )


__all__ = [
    "ExplorationConfig",
    "ExplorationResult",
    "ExplorationStrategy",
    "PathResult",
    "StateSignature",
    "T",
    "WorkItem",
]
