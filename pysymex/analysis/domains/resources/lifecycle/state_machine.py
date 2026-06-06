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

"""Generic resource lifecycle state-machine definitions."""

from __future__ import annotations

from collections.abc import Iterable

from pysymex.analysis.domains.resources.lifecycle.transition_specs import (
    db_connection_transition_spec,
    db_transaction_transition_spec,
    file_transition_spec,
    generic_transition_spec,
    lock_transition_spec,
    memory_transition_spec,
    socket_transition_spec,
)
from pysymex.analysis.domains.resources.types import ResourceKind, ResourceState, StateTransition

TransitionSpec = tuple[ResourceState, set[ResourceState], list[StateTransition]]


class ResourceStateMachine:
    """Finite state machine defining valid resource lifecycle transitions.

    Initialises with resource-kind-specific transition specs (file, lock,
    socket, DB, etc.) and exposes queries for valid transitions.

    Attributes:
        resource_kind: The kind of resource this machine models.
    """

    def __init__(self, resource_kind: ResourceKind) -> None:
        self.resource_kind = resource_kind
        self._transitions: dict[tuple[ResourceState, str], StateTransition] = {}
        self._initial_state = ResourceState.UNINITIALIZED
        self._final_states: set[ResourceState] = set()
        self._setup_transitions()

    def _add_transitions(self, transitions: Iterable[StateTransition]) -> None:
        for transition in transitions:
            self._transitions[(transition.from_state, transition.action)] = transition

    def _apply_spec(self, spec: TransitionSpec) -> None:
        self._initial_state, self._final_states, transitions = spec
        self._add_transitions(transitions)

    def _setup_transitions(self) -> None:
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
        self._apply_spec(file_transition_spec())

    def _setup_lock_transitions(self) -> None:
        self._apply_spec(lock_transition_spec())

    def _setup_memory_transitions(self) -> None:
        self._apply_spec(memory_transition_spec())

    def _setup_db_connection_transitions(self) -> None:
        self._apply_spec(db_connection_transition_spec())

    def _setup_db_transaction_transitions(self) -> None:
        self._apply_spec(db_transaction_transition_spec())

    def _setup_socket_transitions(self) -> None:
        self._apply_spec(socket_transition_spec())

    def _setup_generic_transitions(self) -> None:
        self._apply_spec(generic_transition_spec())

    def can_transition(self, from_state: ResourceState, action: str) -> bool:
        """Return ``True`` if *action* is valid from *from_state*."""
        return (from_state, action) in self._transitions

    def get_transition(self, from_state: ResourceState, action: str) -> StateTransition | None:
        """Return the transition for *action* from *from_state*, or ``None``."""
        return self._transitions.get((from_state, action))

    def is_final_state(self, state: ResourceState) -> bool:
        """Return ``True`` if *state* is an accepting (properly closed) state."""
        return state in self._final_states

    @property
    def initial_state(self) -> ResourceState:
        return self._initial_state
