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
    DOUBLE_CLOSE = auto()
    DOUBLE_FREE = auto()
    DOUBLE_RELEASE = auto()
    DOUBLE_ACQUIRE = auto()
    INVALID_STATE_TRANSITION = auto()
    MISSING_INITIALIZATION = auto()
    DEADLOCK_POTENTIAL = auto()
    LOCK_ORDER_VIOLATION = auto()
    UNCOMMITTED_TRANSACTION = auto()
    OPERATION_OUTSIDE_TRANSACTION = auto()
    MISSING_CONTEXT_MANAGER = auto()
    CONTEXT_MANAGER_MISUSE = auto()


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
        loc = f" at line {self .line_number }" if self.line_number else ""
        res = f" ({self .resource_name })" if self.resource_name else ""
        state = f" [state: {self .current_state .name }]" if self.current_state else ""
        return f"[{self .kind .name }]{loc }{res }{state }: {self .message }"


@dataclass
class StateTransition:
    """Represents a valid state transition."""

    from_state: ResourceState
    to_state: ResourceState
    action: str
    preconditions: list[str] = field(default_factory=list[str])
    postconditions: list[str] = field(default_factory=list[str])
