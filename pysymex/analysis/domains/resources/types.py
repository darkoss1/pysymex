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

"""Resource lifecycle types, enums, and data classes.

Extracted from lifecycle.py for maintainability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto


class ResourceKind(Enum):
    """Types of resources tracked."""

    FILE = auto()
    LOCK = auto()
    MUTEX = auto()
    SEMAPHORE = auto()
    MEMORY = auto()
    SOCKET = auto()
    DATABASE_CONNECTION = auto()
    DATABASE_CURSOR = auto()
    DATABASE_TRANSACTION = auto()
    THREAD = auto()
    PROCESS = auto()
    TEMPORARY_FILE = auto()
    CONTEXT_MANAGER = auto()


class ResourceState(Enum):
    """Possible states of a resource."""

    UNINITIALIZED = auto()
    INITIALIZED = auto()
    OPEN = auto()
    CLOSED = auto()
    ACQUIRED = auto()
    RELEASED = auto()
    ALLOCATED = auto()
    FREED = auto()
    FILE_OPEN_READ = auto()
    FILE_OPEN_WRITE = auto()
    FILE_OPEN_APPEND = auto()
    FILE_OPEN_READWRITE = auto()
    FILE_CLOSED = auto()
    FILE_EOF = auto()
    LOCK_UNLOCKED = auto()
    LOCK_LOCKED = auto()
    LOCK_WAITING = auto()
    CONNECTED = auto()
    DISCONNECTED = auto()
    CONNECTING = auto()
    TRANSACTION_NONE = auto()
    TRANSACTION_ACTIVE = auto()
    TRANSACTION_COMMITTED = auto()
    TRANSACTION_ROLLED_BACK = auto()
    ERROR = auto()
    LEAKED = auto()


class ResourceIssueKind(Enum):
    """Types of resource lifecycle issues."""

    RESOURCE_LEAK = auto()
    POTENTIAL_LEAK = auto()
    USE_AFTER_CLOSE = auto()
    USE_AFTER_FREE = auto()
    USE_AFTER_RELEASE = auto()
    USE_AFTER_DISCONNECT = auto()
    DOUBLE_CLOSE = auto()
    DOUBLE_FREE = auto()
    DOUBLE_RELEASE = auto()
    DOUBLE_DISCONNECT = auto()
    DOUBLE_ACQUIRE = auto()
    INVALID_STATE_TRANSITION = auto()
    MISSING_INITIALIZATION = auto()
    DEADLOCK_POTENTIAL = auto()
    LOCK_ORDER_VIOLATION = auto()
    UNCOMMITTED_TRANSACTION = auto()
    OPERATION_OUTSIDE_TRANSACTION = auto()
    MISSING_CONTEXT_MANAGER = auto()
    CONTEXT_MANAGER_MISUSE = auto()


class ResourceSafetyProofStatus(Enum):
    """Status for a resource lifecycle safety proof."""

    PROVEN_SAFE = auto()
    UNSAFE = auto()
    INCONCLUSIVE = auto()
    NOT_TRACKED = auto()


class ResourceSafetyProofReason(Enum):
    """Machine-readable reason for a non-proven resource safety proof."""

    RESOURCE_NOT_TRACKED = auto()
    UNSAFE_FINAL_STATE_REACHABLE = auto()
    SOLVER_UNKNOWN = auto()


@dataclass(frozen=True, slots=True)
class ResourceSafetyProof:
    """Structured result for resource lifecycle safety queries."""

    status: ResourceSafetyProofStatus
    reason: ResourceSafetyProofReason | None = None
    message: str | None = None

    @property
    def is_safe(self) -> bool:
        """Return true only when resource safety is proved."""
        return self.status is ResourceSafetyProofStatus.PROVEN_SAFE

    @property
    def is_unsafe(self) -> bool:
        """Return true when an unsafe final state is reachable."""
        return self.status is ResourceSafetyProofStatus.UNSAFE

    @property
    def is_inconclusive(self) -> bool:
        """Return true when solver uncertainty prevents a safety proof."""
        return self.status is ResourceSafetyProofStatus.INCONCLUSIVE

    def as_legacy_tuple(self) -> tuple[bool, str | None]:
        """Return the historical ``(safe, reason)`` tuple representation."""
        return (self.is_safe, self.message)

    @staticmethod
    def proven_safe() -> ResourceSafetyProof:
        """Create a proof result for resources proven safe."""
        return ResourceSafetyProof(ResourceSafetyProofStatus.PROVEN_SAFE)

    @staticmethod
    def unsafe(
        message: str = "Resource may not be properly closed/released",
    ) -> ResourceSafetyProof:
        """Create a proof result for reachable unsafe resource states."""
        return ResourceSafetyProof(
            ResourceSafetyProofStatus.UNSAFE,
            ResourceSafetyProofReason.UNSAFE_FINAL_STATE_REACHABLE,
            message,
        )

    @staticmethod
    def inconclusive(
        message: str = "Resource safety proof inconclusive: solver returned unknown",
    ) -> ResourceSafetyProof:
        """Create a proof result for solver-inconclusive resource safety queries."""
        return ResourceSafetyProof(
            ResourceSafetyProofStatus.INCONCLUSIVE,
            ResourceSafetyProofReason.SOLVER_UNKNOWN,
            message,
        )

    @staticmethod
    def not_tracked(message: str = "Resource not tracked") -> ResourceSafetyProof:
        """Create a proof result for an untracked resource name."""
        return ResourceSafetyProof(
            ResourceSafetyProofStatus.NOT_TRACKED,
            ResourceSafetyProofReason.RESOURCE_NOT_TRACKED,
            message,
        )


@dataclass
class ResourceIssue:
    """Represents a detected resource lifecycle issue."""

    kind: ResourceIssueKind
    message: str
    resource_kind: ResourceKind | None = None
    resource_name: str | None = None
    current_state: ResourceState | None = None
    expected_states: list[ResourceState] | None = None
    location: str | None = None
    line_number: int | None = None
    constraints: list[object] = field(default_factory=list[object])
    counterexample: dict[str, object] = field(default_factory=dict[str, object])
    severity: str = "error"

    def format(self) -> str:
        """Format issue for display."""
        loc = f" at line {self.line_number}" if self.line_number else ""
        res = f" ({self.resource_name})" if self.resource_name else ""
        state = f" [state: {self.current_state.name}]" if self.current_state else ""
        return f"[{self.kind.name}]{loc}{res}{state}: {self.message}"


@dataclass
class StateTransition:
    """Represents a valid state transition."""

    from_state: ResourceState
    to_state: ResourceState
    action: str
    preconditions: list[str] = field(default_factory=list[str])
    postconditions: list[str] = field(default_factory=list[str])
