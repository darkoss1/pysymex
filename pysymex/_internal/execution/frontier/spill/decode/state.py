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

"""VMState reconstruction and digest validation for frontier spill payloads."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.frontier.checkpoints import FrontierReconstructionStatus
from pysymex._internal.execution.frontier.entries import FrontierMaterializationError
from pysymex._internal.execution.frontier.obligations.digests import state_shadow_digest
from pysymex._internal.execution.frontier.spill.codec.digests import (
    json_digest_value,
    spill_payload_integrity_digest,
)
from pysymex._internal.execution.frontier.spill.codec.payloads import SPILL_FORMAT_VERSION
from pysymex._internal.execution.frontier.spill.detector.decoding import decode_detector_issues
from pysymex._internal.execution.frontier.spill.detector.types import SpillDetectorDecodeError
from pysymex._internal.execution.frontier.spill.fields.decode import (
    int_sequence,
    optional_str,
    optional_str_tuple,
    raise_format_error,
    required_int,
    required_json_value,
    required_str,
    str_sequence,
)
from pysymex._internal.execution.frontier.spill.instructions.decoding import (
    decode_current_instructions,
)
from pysymex._internal.execution.frontier.spill.instructions.types import (
    SpillInstructionDecodeError,
)
from pysymex._internal.execution.frontier.spill.metadata.blocks import decode_block_stack
from pysymex._internal.execution.frontier.spill.metadata.loops import (
    decode_loop_counters,
    decode_loop_iterations,
)
from pysymex._internal.execution.frontier.spill.metadata.types import SpillMetadataDecodeError
from pysymex._internal.execution.frontier.spill.metadata.writes import decode_write_events
from pysymex._internal.execution.frontier.spill.values.decoding import decode_spill_value_table
from pysymex._internal.execution.frontier.spill.values.types import SpillValueDecodeError

from .collections import memory_values, named_values, optional_stack_value, stack_values
from .constraints import path_constraints

if TYPE_CHECKING:
    from collections.abc import Mapping


def state_from_spill_payload(payload: Mapping[str, object]) -> VMState:
    """Reconstruct and validate a VMState from a spill payload."""
    capsule_id = required_str(payload, "capsule_id")
    version = required_int(payload, "version")
    if version != SPILL_FORMAT_VERSION:
        raise FrontierMaterializationError(
            capsule_id=capsule_id,
            status=FrontierReconstructionStatus.SPILL_FORMAT_MISMATCH,
        )
    expected_spill_digest = required_str(payload, "expected_spill_digest")
    if spill_payload_integrity_digest(payload) != expected_spill_digest:
        raise FrontierMaterializationError(
            capsule_id=capsule_id,
            status=FrontierReconstructionStatus.SPILL_FORMAT_MISMATCH,
        )
    try:
        value_table = decode_spill_value_table(payload.get("values"))
        deferred_detector_issues = decode_detector_issues(payload.get("deferred_detector_issues"))
        block_stack = decode_block_stack(payload.get("block_stack"))
        write_events = decode_write_events(payload.get("write_events"))
        loop_iterations = decode_loop_iterations(payload.get("loop_iterations"))
        loop_counters = decode_loop_counters(payload.get("loop_counters"))
        current_instructions = decode_current_instructions(payload.get("current_instructions"))
    except (
        SpillDetectorDecodeError,
        SpillInstructionDecodeError,
        SpillMetadataDecodeError,
        SpillValueDecodeError,
    ):
        raise_format_error(payload)

    state = VMState(
        stack=stack_values(payload, "stack", value_table),
        local_vars=named_values(payload, "local_vars", value_table),
        global_vars=named_values(payload, "global_vars", value_table),
        memory=memory_values(payload, "memory", value_table),
        path_constraints=path_constraints(payload, capsule_id),
        pc=required_int(payload, "pc"),
        visited_pcs=set(int_sequence(payload, "visited_pcs")),
        path_id=required_int(payload, "path_id"),
        depth=required_int(payload, "depth"),
        block_stack=block_stack,
        current_instructions=current_instructions,
        active_exception=optional_stack_value(payload, "active_exception", value_table),
        pending_reraise_exception=optional_stack_value(
            payload,
            "pending_reraise_exception",
            value_table,
        ),
        deferred_detector_issues=deferred_detector_issues,
        pending_constraint_count=required_int(payload, "pending_constraint_count"),
        last_inconclusive_feasibility_len=required_int(
            payload,
            "last_inconclusive_feasibility_len",
        ),
        loop_iterations=loop_iterations,
        loop_counters=loop_counters,
        freed_vars=set(str_sequence(payload, "freed_vars")),
        open_resources=required_int(payload, "open_resources"),
        write_events=write_events,
    )
    state.pending_kw_names = optional_str_tuple(payload, "pending_kw_names")
    state.current_coro_id = optional_str(payload, "current_coro_id")

    expected_digest = required_json_value(payload, "expected_digest")
    actual_digest = json_digest_value(state_shadow_digest(state))
    if actual_digest != expected_digest:
        raise FrontierMaterializationError(
            capsule_id=capsule_id,
            status=FrontierReconstructionStatus.DIGEST_MISMATCH,
        )
    return state
