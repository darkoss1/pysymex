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

"""Reconstruction of VMState parity artifacts from frontier snapshots."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.state.record import VMState

if TYPE_CHECKING:
    from pysymex._internal.execution.frontier.checkpoint.snapshot.record import (
        FrontierStateSnapshot,
    )


def reconstruct_snapshot(snapshot: FrontierStateSnapshot) -> VMState:
    """Rebuild a VMState parity artifact from the compact snapshot."""
    reconstructed = VMState(
        stack=list(snapshot.stack),
        local_vars=dict(snapshot.local_vars),
        global_vars=dict(snapshot.global_vars),
        path_constraints=list(snapshot.path_constraints),
        pc=snapshot.pc,
        visited_pcs=set(snapshot.visited_pcs),
        memory=dict(snapshot.memory),
        path_id=snapshot.path_id,
        depth=snapshot.depth,
        block_stack=list(snapshot.block_stack),
        call_stack=list(snapshot.call_stack),
        contract_frames=list(snapshot.contract_frames),
        current_instructions=(
            list(snapshot.current_instructions)
            if snapshot.current_instructions is not None
            else None
        ),
        active_exception=snapshot.active_exception,
        pending_reraise_exception=snapshot.pending_reraise_exception,
        deferred_detector_issues=list(snapshot.deferred_detector_issues),
        pending_constraint_count=snapshot.pending_constraint_count,
        last_inconclusive_feasibility_len=snapshot.last_inconclusive_feasibility_len,
        loop_iterations=dict(snapshot.loop_iterations),
        loop_counters=dict(snapshot.loop_counters),
        freed_vars=set(snapshot.freed_vars),
        prev_loop_states=dict(snapshot.prev_loop_states),
        branch_trace=snapshot.branch_trace,
        open_resources=snapshot.open_resources,
        write_events=list(snapshot.write_events),
    )
    reconstructed.pending_kw_names = snapshot.pending_kw_names
    reconstructed.current_coro_id = snapshot.current_coro_id
    reconstructed.awaitable_results = dict(snapshot.awaitable_results)
    reconstructed.invalidate_cached_hash()
    return reconstructed
