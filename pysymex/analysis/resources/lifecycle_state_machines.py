"""Resource state machine definitions and tracked resource dataclass.

Extracted from lifecycle.py for maintainability.
"""

from __future__ import annotations


from collections.abc import Callable

from dataclasses import dataclass, field


import z3


from pysymex.analysis.resources.lifecycle_types import (
    ResourceKind,
    ResourceState,
    StateTransition,
)


class ResourceStateMachine:
    """
    State machine model for resource lifecycle.

    Defines valid transitions and checks invariants.
    """

    def __init__(self, resource_kind: ResourceKind):
        self.resource_kind = resource_kind

        self._transitions: dict[tuple[ResourceState, str], StateTransition] = {}

        self._invariants: list[Callable[[ResourceState], bool]] = []

        self._initial_state = ResourceState.UNINITIALIZED

        self._final_states: set[ResourceState] = set()

        self._setup_transitions()

    def _setup_transitions(self) -> None:
        """Set up transitions based on resource kind."""

        if self.resource_kind == ResourceKind.FILE:
            self._setup_file_transitions()

        elif self.resource_kind in {ResourceKind.LOCK, ResourceKind.MUTEX}:
            self._setup_lock_transitions()

        elif self.resource_kind == ResourceKind.MEMORY:
            self._setup_memory_transitions()

        elif self.resource_kind == ResourceKind.DATABASE_CONNECTION:
            self._setup_db_connection_transitions()

        elif self.resource_kind == ResourceKind.DATABASE_TRANSACTION:
            self._setup_db_transaction_transitions()

        elif self.resource_kind == ResourceKind.SOCKET:
            self._setup_socket_transitions()

        else:
            self._setup_generic_transitions()

    def _setup_file_transitions(self) -> None:
        """Set up file state machine."""

        self._initial_state = ResourceState.UNINITIALIZED

        self._final_states = {ResourceState.FILE_CLOSED, ResourceState.UNINITIALIZED}

        transitions = [
            StateTransition(ResourceState.UNINITIALIZED, ResourceState.FILE_OPEN_READ, "open_read"),
            StateTransition(
                ResourceState.UNINITIALIZED, ResourceState.FILE_OPEN_WRITE, "open_write"
            ),
            StateTransition(
                ResourceState.UNINITIALIZED, ResourceState.FILE_OPEN_APPEND, "open_append"
            ),
            StateTransition(
                ResourceState.UNINITIALIZED, ResourceState.FILE_OPEN_READWRITE, "open_readwrite"
            ),
            StateTransition(ResourceState.FILE_OPEN_READ, ResourceState.FILE_OPEN_READ, "read"),
            StateTransition(ResourceState.FILE_OPEN_READ, ResourceState.FILE_EOF, "read_eof"),
            StateTransition(ResourceState.FILE_OPEN_READ, ResourceState.FILE_CLOSED, "close"),
            StateTransition(ResourceState.FILE_OPEN_WRITE, ResourceState.FILE_OPEN_WRITE, "write"),
            StateTransition(ResourceState.FILE_OPEN_WRITE, ResourceState.FILE_CLOSED, "close"),
            StateTransition(
                ResourceState.FILE_OPEN_APPEND, ResourceState.FILE_OPEN_APPEND, "write"
            ),
            StateTransition(ResourceState.FILE_OPEN_APPEND, ResourceState.FILE_CLOSED, "close"),
            StateTransition(
                ResourceState.FILE_OPEN_READWRITE, ResourceState.FILE_OPEN_READWRITE, "read"
            ),
            StateTransition(
                ResourceState.FILE_OPEN_READWRITE, ResourceState.FILE_OPEN_READWRITE, "write"
            ),
            StateTransition(ResourceState.FILE_OPEN_READWRITE, ResourceState.FILE_CLOSED, "close"),
            StateTransition(ResourceState.FILE_EOF, ResourceState.FILE_CLOSED, "close"),
        ]

        for t in transitions:
            self._transitions[(t.from_state, t.action)] = t

    def _setup_lock_transitions(self) -> None:
        """Set up lock state machine."""

        self._initial_state = ResourceState.LOCK_UNLOCKED

        self._final_states = {ResourceState.LOCK_UNLOCKED}

        transitions = [
            StateTransition(ResourceState.LOCK_UNLOCKED, ResourceState.LOCK_LOCKED, "acquire"),
            StateTransition(
                ResourceState.LOCK_UNLOCKED, ResourceState.LOCK_WAITING, "acquire_blocking"
            ),
            StateTransition(ResourceState.LOCK_WAITING, ResourceState.LOCK_LOCKED, "acquired"),
            StateTransition(ResourceState.LOCK_LOCKED, ResourceState.LOCK_UNLOCKED, "release"),
        ]

        for t in transitions:
            self._transitions[(t.from_state, t.action)] = t

    def _setup_memory_transitions(self) -> None:
        """Set up memory state machine."""

        self._initial_state = ResourceState.UNINITIALIZED

        self._final_states = {ResourceState.FREED, ResourceState.UNINITIALIZED}

        transitions = [
            StateTransition(ResourceState.UNINITIALIZED, ResourceState.ALLOCATED, "allocate"),
            StateTransition(ResourceState.ALLOCATED, ResourceState.ALLOCATED, "read"),
            StateTransition(ResourceState.ALLOCATED, ResourceState.ALLOCATED, "write"),
            StateTransition(ResourceState.ALLOCATED, ResourceState.FREED, "free"),
        ]

        for t in transitions:
            self._transitions[(t.from_state, t.action)] = t

    def _setup_db_connection_transitions(self) -> None:
        """Set up database connection state machine."""

        self._initial_state = ResourceState.DISCONNECTED

        self._final_states = {ResourceState.DISCONNECTED}

        transitions = [
            StateTransition(ResourceState.DISCONNECTED, ResourceState.CONNECTING, "connect_start"),
            StateTransition(ResourceState.CONNECTING, ResourceState.CONNECTED, "connect_complete"),
            StateTransition(ResourceState.CONNECTING, ResourceState.DISCONNECTED, "connect_failed"),
            StateTransition(ResourceState.CONNECTED, ResourceState.CONNECTED, "execute"),
            StateTransition(ResourceState.CONNECTED, ResourceState.DISCONNECTED, "disconnect"),
        ]

        for t in transitions:
            self._transitions[(t.from_state, t.action)] = t

    def _setup_db_transaction_transitions(self) -> None:
        """Set up database transaction state machine."""

        self._initial_state = ResourceState.TRANSACTION_NONE

        self._final_states = {
            ResourceState.TRANSACTION_NONE,
            ResourceState.TRANSACTION_COMMITTED,
            ResourceState.TRANSACTION_ROLLED_BACK,
        }

        transitions = [
            StateTransition(
                ResourceState.TRANSACTION_NONE, ResourceState.TRANSACTION_ACTIVE, "begin"
            ),
            StateTransition(
                ResourceState.TRANSACTION_ACTIVE, ResourceState.TRANSACTION_ACTIVE, "execute"
            ),
            StateTransition(
                ResourceState.TRANSACTION_ACTIVE, ResourceState.TRANSACTION_COMMITTED, "commit"
            ),
            StateTransition(
                ResourceState.TRANSACTION_ACTIVE, ResourceState.TRANSACTION_ROLLED_BACK, "rollback"
            ),
        ]

        for t in transitions:
            self._transitions[(t.from_state, t.action)] = t

    def _setup_socket_transitions(self) -> None:
        """Set up socket state machine."""

        self._initial_state = ResourceState.UNINITIALIZED

        self._final_states = {ResourceState.CLOSED}

        transitions = [
            StateTransition(ResourceState.UNINITIALIZED, ResourceState.INITIALIZED, "create"),
            StateTransition(ResourceState.INITIALIZED, ResourceState.CONNECTING, "connect_start"),
            StateTransition(ResourceState.CONNECTING, ResourceState.CONNECTED, "connect_complete"),
            StateTransition(ResourceState.CONNECTED, ResourceState.CONNECTED, "send"),
            StateTransition(ResourceState.CONNECTED, ResourceState.CONNECTED, "recv"),
            StateTransition(ResourceState.CONNECTED, ResourceState.CLOSED, "close"),
            StateTransition(ResourceState.INITIALIZED, ResourceState.CLOSED, "close"),
        ]

        for t in transitions:
            self._transitions[(t.from_state, t.action)] = t

    def _setup_generic_transitions(self) -> None:
        """Set up generic resource state machine."""

        self._initial_state = ResourceState.UNINITIALIZED

        self._final_states = {ResourceState.CLOSED, ResourceState.RELEASED, ResourceState.FREED}

        transitions = [
            StateTransition(ResourceState.UNINITIALIZED, ResourceState.OPEN, "open"),
            StateTransition(ResourceState.UNINITIALIZED, ResourceState.ACQUIRED, "acquire"),
            StateTransition(ResourceState.UNINITIALIZED, ResourceState.ALLOCATED, "allocate"),
            StateTransition(ResourceState.OPEN, ResourceState.CLOSED, "close"),
            StateTransition(ResourceState.ACQUIRED, ResourceState.RELEASED, "release"),
            StateTransition(ResourceState.ALLOCATED, ResourceState.FREED, "free"),
        ]

        for t in transitions:
            self._transitions[(t.from_state, t.action)] = t

    def can_transition(self, from_state: ResourceState, action: str) -> bool:
        """Check if transition is valid."""

        return (from_state, action) in self._transitions

    def get_transition(self, from_state: ResourceState, action: str) -> StateTransition | None:
        """Get transition if valid."""

        return self._transitions.get((from_state, action))

    def is_final_state(self, state: ResourceState) -> bool:
        """Check if state is a valid final state."""

        return state in self._final_states

    @property
    def initial_state(self) -> ResourceState:
        return self._initial_state


@dataclass
class TrackedResource:
    """Tracks a single resource instance."""

    name: str

    kind: ResourceKind

    state: ResourceState

    state_machine: ResourceStateMachine

    created_at: int | None = None

    last_action_at: int | None = None

    history: list[tuple[str, ResourceState, int | None]] = field(
        default_factory=list[tuple[str, ResourceState, int | None]]
    )

    z3_state: z3.ExprRef | None = None

    def record_action(self, action: str, new_state: ResourceState, line: int | None = None) -> None:
        """Record an action taken on this resource."""

        self.history.append((action, new_state, line))

        self.state = new_state

        self.last_action_at = line
