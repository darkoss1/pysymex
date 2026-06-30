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

"""VMState-to-frontier-snapshot capture."""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar

from pysymex._internal.execution.frontier.evidence import havoc_root_count
from pysymex._internal.execution.frontier.obligations.digests import state_structural_hash

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.frontier.checkpoint.snapshot.record import (
        FrontierStateSnapshot,
    )

SnapshotT = TypeVar("SnapshotT", bound="FrontierStateSnapshot")


def snapshot_from_state(
    snapshot_type: type[SnapshotT],
    state: VMState,
) -> SnapshotT:
    """Build a compact snapshot from digest-visible ``VMState`` facts."""
    return snapshot_type(
        stack=tuple(state.stack),
        local_vars=state.local_vars.sorted_items(),
        global_vars=state.global_vars.sorted_items(),
        memory=state.memory.sorted_items(),
        path_constraints=tuple(state.path_constraints.to_list()),
        constraint_atom_ids=state.path_constraints.sorted_constraint_hashes(),
        havoc_live_count=havoc_root_count(
            (
                *state.stack,
                *state.local_vars.values(),
                *state.global_vars.values(),
                *state.memory.values(),
                *((state.active_exception,) if state.active_exception is not None else ()),
                *(
                    (state.pending_reraise_exception,)
                    if state.pending_reraise_exception is not None
                    else ()
                ),
                *state.awaitable_results.values(),
            ),
        ),
        pc=state.pc,
        visited_pcs=frozenset(state.visited_pcs),
        path_id=state.path_id,
        depth=state.depth,
        state_structural_hash=state_structural_hash(state),
        block_stack=tuple(state.block_stack),
        call_stack=tuple(state.call_stack),
        contract_frames=tuple(state.contract_frames),
        current_instructions=(
            tuple(state.current_instructions) if state.current_instructions is not None else None
        ),
        active_exception=state.active_exception,
        pending_reraise_exception=state.pending_reraise_exception,
        deferred_detector_issues=tuple(state.deferred_detector_issues),
        pending_constraint_count=state.pending_constraint_count,
        last_inconclusive_feasibility_len=state.last_inconclusive_feasibility_len,
        loop_iterations=tuple(
            sorted(state.loop_iterations.items(), key=lambda item: repr(item[0])),
        ),
        loop_counters=tuple(sorted(state.loop_counters.items())),
        freed_vars=frozenset(state.freed_vars),
        prev_loop_states=tuple(
            sorted(state.prev_loop_states.items(), key=lambda item: repr(item[0])),
        ),
        branch_trace=state.branch_trace,
        open_resources=state.open_resources,
        write_events=tuple(state.write_events),
        pending_kw_names=state.pending_kw_names,
        current_coro_id=state.current_coro_id,
        awaitable_results=tuple(sorted(state.awaitable_results.items())),
    )
