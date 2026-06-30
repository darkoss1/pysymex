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

"""Structural matching for compact frontier snapshots."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.frontier.checkpoint.matching import (
    awaitable_results_match,
    branch_traces_match,
    memory_values_match,
    named_values_match,
    objects_match,
    objects_match_optional,
    previous_loop_states_match,
    value_matches,
    values_match,
    z3_constraint_multisets_match,
)

if TYPE_CHECKING:
    from pysymex._internal.execution.frontier.checkpoint.snapshot.record import (
        FrontierStateSnapshot,
    )


def snapshots_structurally_match(
    left: FrontierStateSnapshot,
    right: FrontierStateSnapshot,
) -> bool:
    """Return whether ``right`` preserves every checkpoint-visible root from ``left``."""
    return (
        left.digest() == right.digest()
        and left.path_id == right.path_id
        and left.depth == right.depth
        and left.pc == right.pc
        and left.state_structural_hash == right.state_structural_hash
        and left.havoc_live_count == right.havoc_live_count
        and left.pending_constraint_count == right.pending_constraint_count
        and z3_constraint_multisets_match(left.path_constraints, right.path_constraints)
        and values_match(left.stack, right.stack)
        and named_values_match(left.local_vars, right.local_vars)
        and named_values_match(left.global_vars, right.global_vars)
        and memory_values_match(left.memory, right.memory)
        and objects_match(left.block_stack, right.block_stack)
        and objects_match(left.call_stack, right.call_stack)
        and objects_match(left.contract_frames, right.contract_frames)
        and objects_match_optional(left.current_instructions, right.current_instructions)
        and value_matches(left.active_exception, right.active_exception)
        and value_matches(left.pending_reraise_exception, right.pending_reraise_exception)
        and objects_match(left.deferred_detector_issues, right.deferred_detector_issues)
        and left.last_inconclusive_feasibility_len == right.last_inconclusive_feasibility_len
        and left.loop_iterations == right.loop_iterations
        and left.loop_counters == right.loop_counters
        and left.freed_vars == right.freed_vars
        and previous_loop_states_match(left.prev_loop_states, right.prev_loop_states)
        and branch_traces_match(left.branch_trace, right.branch_trace)
        and left.open_resources == right.open_resources
        and objects_match(left.write_events, right.write_events)
        and left.pending_kw_names == right.pending_kw_names
        and left.current_coro_id == right.current_coro_id
        and awaitable_results_match(left.awaitable_results, right.awaitable_results)
    )
