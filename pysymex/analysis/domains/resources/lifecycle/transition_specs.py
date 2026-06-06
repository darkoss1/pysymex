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

"""Transition specifications defining valid resource state changes."""

from __future__ import annotations

from pysymex.analysis.domains.resources.types import ResourceState, StateTransition

TransitionSpec = tuple[ResourceState, set[ResourceState], list[StateTransition]]


def file_transition_spec() -> TransitionSpec:
    return (
        ResourceState.UNINITIALIZED,
        {ResourceState.FILE_CLOSED, ResourceState.UNINITIALIZED},
        [
            StateTransition(ResourceState.UNINITIALIZED, ResourceState.FILE_OPEN_READ, "open_read"),
            StateTransition(
                ResourceState.UNINITIALIZED, ResourceState.FILE_OPEN_WRITE, "open_write"
            ),
            StateTransition(
                ResourceState.UNINITIALIZED, ResourceState.FILE_OPEN_APPEND, "open_append"
            ),
            StateTransition(
                ResourceState.UNINITIALIZED,
                ResourceState.FILE_OPEN_READWRITE,
                "open_readwrite",
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
        ],
    )


def lock_transition_spec() -> TransitionSpec:
    return (
        ResourceState.LOCK_UNLOCKED,
        {ResourceState.LOCK_UNLOCKED},
        [
            StateTransition(ResourceState.LOCK_UNLOCKED, ResourceState.LOCK_LOCKED, "acquire"),
            StateTransition(
                ResourceState.LOCK_UNLOCKED, ResourceState.LOCK_WAITING, "acquire_blocking"
            ),
            StateTransition(ResourceState.LOCK_WAITING, ResourceState.LOCK_LOCKED, "acquired"),
            StateTransition(ResourceState.LOCK_LOCKED, ResourceState.LOCK_UNLOCKED, "release"),
        ],
    )


def memory_transition_spec() -> TransitionSpec:
    return (
        ResourceState.UNINITIALIZED,
        {ResourceState.FREED, ResourceState.UNINITIALIZED},
        [
            StateTransition(ResourceState.UNINITIALIZED, ResourceState.ALLOCATED, "allocate"),
            StateTransition(ResourceState.ALLOCATED, ResourceState.ALLOCATED, "read"),
            StateTransition(ResourceState.ALLOCATED, ResourceState.ALLOCATED, "write"),
            StateTransition(ResourceState.ALLOCATED, ResourceState.FREED, "free"),
        ],
    )


def db_connection_transition_spec() -> TransitionSpec:
    return (
        ResourceState.DISCONNECTED,
        {ResourceState.DISCONNECTED},
        [
            StateTransition(ResourceState.DISCONNECTED, ResourceState.CONNECTING, "connect_start"),
            StateTransition(ResourceState.CONNECTING, ResourceState.CONNECTED, "connect_complete"),
            StateTransition(ResourceState.CONNECTING, ResourceState.DISCONNECTED, "connect_failed"),
            StateTransition(ResourceState.CONNECTED, ResourceState.CONNECTED, "execute"),
            StateTransition(ResourceState.CONNECTED, ResourceState.DISCONNECTED, "disconnect"),
        ],
    )


def db_transaction_transition_spec() -> TransitionSpec:
    return (
        ResourceState.TRANSACTION_NONE,
        {
            ResourceState.TRANSACTION_NONE,
            ResourceState.TRANSACTION_COMMITTED,
            ResourceState.TRANSACTION_ROLLED_BACK,
        },
        [
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
                ResourceState.TRANSACTION_ACTIVE,
                ResourceState.TRANSACTION_ROLLED_BACK,
                "rollback",
            ),
        ],
    )


def socket_transition_spec() -> TransitionSpec:
    return (
        ResourceState.UNINITIALIZED,
        {ResourceState.CLOSED},
        [
            StateTransition(ResourceState.UNINITIALIZED, ResourceState.INITIALIZED, "create"),
            StateTransition(ResourceState.INITIALIZED, ResourceState.CONNECTING, "connect_start"),
            StateTransition(ResourceState.CONNECTING, ResourceState.CONNECTED, "connect_complete"),
            StateTransition(ResourceState.CONNECTED, ResourceState.CONNECTED, "send"),
            StateTransition(ResourceState.CONNECTED, ResourceState.CONNECTED, "recv"),
            StateTransition(ResourceState.CONNECTED, ResourceState.CLOSED, "close"),
            StateTransition(ResourceState.INITIALIZED, ResourceState.CLOSED, "close"),
        ],
    )


def generic_transition_spec() -> TransitionSpec:
    return (
        ResourceState.UNINITIALIZED,
        {ResourceState.CLOSED, ResourceState.RELEASED, ResourceState.FREED},
        [
            StateTransition(ResourceState.UNINITIALIZED, ResourceState.OPEN, "open"),
            StateTransition(ResourceState.UNINITIALIZED, ResourceState.ACQUIRED, "acquire"),
            StateTransition(ResourceState.UNINITIALIZED, ResourceState.ALLOCATED, "allocate"),
            StateTransition(ResourceState.OPEN, ResourceState.CLOSED, "close"),
            StateTransition(ResourceState.ACQUIRED, ResourceState.RELEASED, "release"),
            StateTransition(ResourceState.ALLOCATED, ResourceState.FREED, "free"),
        ],
    )
