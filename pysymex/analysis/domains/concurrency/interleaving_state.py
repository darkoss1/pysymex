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

"""Data models for DPOR interleaving exploration: transitions and search state."""

from __future__ import annotations

from dataclasses import dataclass, field

from pysymex.analysis.domains.concurrency.models import MemoryOperation


@dataclass(frozen=True)
class Transition:
    """A single step in a thread interleaving schedule."""

    thread_id: str
    operation: MemoryOperation
    op_id: int
    enabled: bool = True


@dataclass
class InterleavingState:
    """Mutable snapshot of DPOR exploration: current schedule, per-thread progress, and backtrack sets."""

    schedule: list[Transition] = field(default_factory=list[Transition])
    thread_states: dict[str, int] = field(default_factory=dict[str, int])
    backtrack_set: set[str] = field(default_factory=set[str])
    done_set: set[str] = field(default_factory=set[str])
    sleep_set: set[str] = field(default_factory=set[str])

    def clone(self) -> InterleavingState:
        """Create a deep copy of this state."""
        return InterleavingState(
            schedule=list(self.schedule),
            thread_states=dict(self.thread_states),
            backtrack_set=set(self.backtrack_set),
            done_set=set(self.done_set),
            sleep_set=set(self.sleep_set),
        )


__all__ = ["InterleavingState", "Transition"]
