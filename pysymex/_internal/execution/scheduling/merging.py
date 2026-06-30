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

"""State-merger handoff policy for scheduled execution states."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.session.state.core import ExecutionSession
    from pysymex._internal.execution.strategies.merger.state import StateMerger


def offer_state_to_merger(
    *,
    session: ExecutionSession,
    state_merger: StateMerger | None,
    state: VMState,
) -> VMState | None:
    """Offer ``state`` to the configured merger before opcode dispatch."""
    if state_merger is None or not state_merger.should_merge(state):
        return state
    merged = state_merger.add_state_for_merge(state)
    if merged is None:
        session.paths_pruned += 1
        return None
    return merged
