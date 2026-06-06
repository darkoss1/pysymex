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

"""Enumerations for concurrency analysis: memory ordering, operation kinds, thread states, and issue types."""

from __future__ import annotations

from enum import Enum, auto


class MemoryOrder(Enum):
    """C/C++-style memory ordering semantics modelled during concurrency analysis."""

    RELAXED = auto()
    ACQUIRE = auto()
    RELEASE = auto()
    ACQ_REL = auto()
    SEQ_CST = auto()


class OperationKind(Enum):
    """Classification of operations that access shared memory or synchronisation primitives."""

    READ = auto()
    WRITE = auto()
    READ_MODIFY_WRITE = auto()
    FENCE = auto()
    LOCK_ACQUIRE = auto()
    LOCK_RELEASE = auto()
    THREAD_CREATE = auto()
    THREAD_JOIN = auto()
    BARRIER = auto()


class ThreadState(Enum):
    """Lifecycle states of a modelled thread."""

    NOT_STARTED = auto()
    RUNNING = auto()
    BLOCKED = auto()
    WAITING = auto()
    TERMINATED = auto()


class ConcurrencyIssueKind(Enum):
    """Taxonomy of concurrency bugs detectable by the analyser."""

    DATA_RACE = auto()
    RACE_CONDITION = auto()
    DEADLOCK = auto()
    POTENTIAL_DEADLOCK = auto()
    LIVELOCK = auto()
    ATOMICITY_VIOLATION = auto()
    LOST_UPDATE = auto()
    MEMORY_ORDER_VIOLATION = auto()
    STALE_READ = auto()
    LOCK_NOT_HELD = auto()
    WRONG_LOCK = auto()
    USE_AFTER_JOIN = auto()
    JOIN_WITHOUT_START = auto()
    SPURIOUS_WAKEUP = auto()
    SIGNAL_SAFETY = auto()


__all__ = ["ConcurrencyIssueKind", "MemoryOrder", "OperationKind", "ThreadState"]
