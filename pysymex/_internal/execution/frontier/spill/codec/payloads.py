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

"""Checkpoint-to-JSON payload assembly for frontier spill files."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.frontier.spill.codec.constraints import (
    UnsupportedConstraintsSentinel,
    constraints_payload,
)
from pysymex._internal.execution.frontier.spill.codec.digests import (
    EXPECTED_DIGEST_KEY,
    EXPECTED_SPILL_DIGEST_KEY,
    json_digest_value,
    spill_payload_integrity_digest,
)
from pysymex._internal.execution.frontier.spill.detector.payloads import detector_issues_payload
from pysymex._internal.execution.frontier.spill.instructions.encoding import (
    current_instructions_payload,
)
from pysymex._internal.execution.frontier.spill.metadata.blocks import block_stack_payload
from pysymex._internal.execution.frontier.spill.metadata.loops import (
    loop_counters_payload,
    loop_iterations_payload,
)
from pysymex._internal.execution.frontier.spill.metadata.writes import write_events_payload
from pysymex._internal.execution.frontier.spill.values.encoding import SpillValueEncoder

if TYPE_CHECKING:
    from pysymex._internal.execution.frontier.checkpoints import FrontierCheckpoint
    from pysymex._internal.execution.frontier.spill.values.types import JsonObject, JsonValue

SPILL_FORMAT_VERSION = 3


def checkpoint_spill_payload(checkpoint: FrontierCheckpoint) -> JsonObject | None:
    """Return a JSON payload for a spill-safe checkpoint or ``None``."""
    if not checkpoint.snapshot_matches_capsule():
        return None

    snapshot = checkpoint.snapshot
    if (
        snapshot.call_stack
        or snapshot.contract_frames
        or snapshot.prev_loop_states
        or len(snapshot.branch_trace) != 0
        or snapshot.awaitable_results
    ):
        return None

    value_encoder = SpillValueEncoder()
    stack = value_encoder.values_payload(snapshot.stack)
    local_vars = value_encoder.named_values_payload(snapshot.local_vars)
    global_vars = value_encoder.named_values_payload(snapshot.global_vars)
    memory = value_encoder.memory_values_payload(snapshot.memory)
    if stack is None or local_vars is None or global_vars is None or memory is None:
        return None
    active_exception = (
        value_encoder.value_ref_payload(snapshot.active_exception)
        if snapshot.active_exception is not None
        else None
    )
    pending_reraise_exception = (
        value_encoder.value_ref_payload(snapshot.pending_reraise_exception)
        if snapshot.pending_reraise_exception is not None
        else None
    )
    if (snapshot.active_exception is not None and active_exception is None) or (
        snapshot.pending_reraise_exception is not None and pending_reraise_exception is None
    ):
        return None
    deferred_detector_issues = detector_issues_payload(snapshot.deferred_detector_issues)
    if deferred_detector_issues is None:
        return None
    block_stack = block_stack_payload(snapshot.block_stack)
    write_events = write_events_payload(snapshot.write_events)
    loop_iterations = loop_iterations_payload(snapshot.loop_iterations)
    loop_counters = loop_counters_payload(snapshot.loop_counters)
    current_instructions = (
        current_instructions_payload(snapshot.current_instructions)
        if snapshot.current_instructions is not None
        else None
    )
    if (
        block_stack is None
        or write_events is None
        or loop_iterations is None
        or loop_counters is None
        or (snapshot.current_instructions is not None and current_instructions is None)
    ):
        return None
    constraints_smt2 = constraints_payload(snapshot.path_constraints)
    if isinstance(constraints_smt2, UnsupportedConstraintsSentinel):
        return None

    pending_kw_names: list[JsonValue] | None = (
        list(snapshot.pending_kw_names) if snapshot.pending_kw_names is not None else None
    )
    visited_pcs: list[JsonValue] = []
    for visited_pc in sorted(snapshot.visited_pcs):
        visited_pcs.append(visited_pc)
    freed_vars: list[JsonValue] = []
    for freed_var in sorted(snapshot.freed_vars):
        freed_vars.append(freed_var)
    payload: JsonObject = {
        "version": SPILL_FORMAT_VERSION,
        "capsule_id": checkpoint.capsule.capsule_id,
        EXPECTED_DIGEST_KEY: json_digest_value(snapshot.digest()),
        "values": value_encoder.value_table_payload(),
        "stack": stack,
        "local_vars": local_vars,
        "global_vars": global_vars,
        "memory": memory,
        "active_exception": active_exception,
        "pending_reraise_exception": pending_reraise_exception,
        "deferred_detector_issues": deferred_detector_issues,
        "block_stack": block_stack,
        "write_events": write_events,
        "loop_iterations": loop_iterations,
        "loop_counters": loop_counters,
        "current_instructions": current_instructions,
        "path_constraints_smt2": constraints_smt2,
        "pc": snapshot.pc,
        "visited_pcs": visited_pcs,
        "path_id": snapshot.path_id,
        "depth": snapshot.depth,
        "pending_constraint_count": snapshot.pending_constraint_count,
        "last_inconclusive_feasibility_len": snapshot.last_inconclusive_feasibility_len,
        "freed_vars": freed_vars,
        "open_resources": snapshot.open_resources,
        "pending_kw_names": pending_kw_names,
        "current_coro_id": snapshot.current_coro_id,
    }
    payload[EXPECTED_SPILL_DIGEST_KEY] = spill_payload_integrity_digest(payload)
    return payload
