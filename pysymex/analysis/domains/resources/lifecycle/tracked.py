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

"""Model for a single tracked resource instance across its lifecycle."""

from __future__ import annotations

from dataclasses import dataclass, field

import z3

from pysymex.analysis.domains.resources.lifecycle.state_machine import ResourceStateMachine
from pysymex.analysis.domains.resources.types import ResourceKind, ResourceState


def _new_history() -> list[tuple[str, ResourceState, int | None]]:
    return []


@dataclass
class TrackedResource:
    """Tracks a single resource instance."""

    name: str
    kind: ResourceKind
    state: ResourceState
    state_machine: ResourceStateMachine
    created_at: int | None = None
    last_action_at: int | None = None
    history: list[tuple[str, ResourceState, int | None]] = field(default_factory=_new_history)
    z3_state: z3.ExprRef | None = None

    def record_action(self, action: str, new_state: ResourceState, line: int | None = None) -> None:
        self.history.append((action, new_state, line))
        self.state = new_state
        self.last_action_at = line
