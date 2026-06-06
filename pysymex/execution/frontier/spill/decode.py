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

"""Decode and validate safe frontier checkpoint spill files."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Never, cast

import z3

from pysymex.core.state.record import VMState
from pysymex.execution.frontier.checkpoints import FrontierReconstructionStatus
from pysymex.execution.frontier.entries import (
    FrontierMaterializationError,
    FrontierQueueEntry,
)
from pysymex.execution.frontier.obligations import state_shadow_digest
from pysymex.execution.frontier.spill.codec import (
    SPILL_FORMAT_VERSION,
    JsonValue,
    json_digest_value,
    spill_payload_integrity_digest,
)
from pysymex.execution.frontier.spill.detectors import (
    SpillDetectorDecodeError,
    decode_detector_issues,
)
from pysymex.execution.frontier.spill.instructions import (
    SpillInstructionDecodeError,
    decode_current_instructions,
)
from pysymex.execution.frontier.spill.metadata import (
    SpillMetadataDecodeError,
    decode_block_stack,
    decode_loop_counters,
    decode_loop_iterations,
    decode_write_events,
)
from pysymex.execution.frontier.spill.values import (
    SpillValueDecodeError,
    decode_spill_value_ref,
    decode_spill_value_table,
)
from pysymex.typing import StackValue

__all__ = ["materialize_spilled_frontier_entry"]


def materialize_spilled_frontier_entry(entry: FrontierQueueEntry) -> VMState:
    """Load and reconstruct a VMState from a spilled compact checkpoint entry."""
    spill_file = entry.spilled_checkpoint_path
    if spill_file is None:
        msg = "frontier entry is not spilled"
        raise ValueError(msg)
    try:
        with spill_file.open("r", encoding="utf-8") as handle:
            raw_payload: object = json.load(handle)
    except OSError as exc:
        raise FrontierMaterializationError(
            capsule_id=str(spill_file),
            status=FrontierReconstructionStatus.SPILL_FORMAT_MISMATCH,
        ) from exc

    payload = _object_payload(raw_payload)
    if payload is None:
        raise FrontierMaterializationError(
            capsule_id=str(spill_file),
            status=FrontierReconstructionStatus.SPILL_FORMAT_MISMATCH,
        )
    return _state_from_spill_payload(payload)


def _object_payload(raw_payload: object) -> Mapping[str, object] | None:
    """Return a string-keyed mapping from decoded JSON."""
    if not isinstance(raw_payload, Mapping):
        return None
    raw_mapping = cast("Mapping[object, object]", raw_payload)
    result: dict[str, object] = {}
    for key, value in raw_mapping.items():
        if not isinstance(key, str):
            return None
        result[key] = value
    return result


def _state_from_spill_payload(payload: Mapping[str, object]) -> VMState:
    """Reconstruct and validate a VMState from a spill payload."""
    capsule_id = _required_str(payload, "capsule_id")
    version = _required_int(payload, "version")
    if version != SPILL_FORMAT_VERSION:
        raise FrontierMaterializationError(
            capsule_id=capsule_id,
            status=FrontierReconstructionStatus.SPILL_FORMAT_MISMATCH,
        )
    expected_spill_digest = _required_str(payload, "expected_spill_digest")
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
        _raise_format_error(payload)

    state = VMState(
        stack=_stack_values(payload, "stack", value_table),
        local_vars=_named_values(payload, "local_vars", value_table),
        global_vars=_named_values(payload, "global_vars", value_table),
        memory=_memory_values(payload, "memory", value_table),
        path_constraints=_path_constraints(payload, capsule_id),
        pc=_required_int(payload, "pc"),
        visited_pcs=set(_int_sequence(payload, "visited_pcs")),
        path_id=_required_int(payload, "path_id"),
        depth=_required_int(payload, "depth"),
        block_stack=block_stack,
        current_instructions=current_instructions,
        active_exception=_optional_stack_value(payload, "active_exception", value_table),
        pending_reraise_exception=_optional_stack_value(
            payload,
            "pending_reraise_exception",
            value_table,
        ),
        deferred_detector_issues=deferred_detector_issues,
        pending_constraint_count=_required_int(payload, "pending_constraint_count"),
        last_inconclusive_feasibility_len=_required_int(
            payload,
            "last_inconclusive_feasibility_len",
        ),
        loop_iterations=loop_iterations,
        loop_counters=loop_counters,
        freed_vars=set(_str_sequence(payload, "freed_vars")),
        open_resources=_required_int(payload, "open_resources"),
        write_events=write_events,
    )
    state.pending_kw_names = _optional_str_tuple(payload, "pending_kw_names")
    state.current_coro_id = _optional_str(payload, "current_coro_id")

    expected_digest = _required_json_value(payload, "expected_digest")
    actual_digest = json_digest_value(state_shadow_digest(state))
    if actual_digest != expected_digest:
        raise FrontierMaterializationError(
            capsule_id=capsule_id,
            status=FrontierReconstructionStatus.DIGEST_MISMATCH,
        )
    return state


def _required_json_value(payload: Mapping[str, object], key: str) -> JsonValue:
    """Return a required JSON value from a decoded mapping."""
    raw_value = payload.get(key)
    if _is_json_value(raw_value):
        return cast("JsonValue", raw_value)
    _raise_format_error(payload)


def _required_str(payload: Mapping[str, object], key: str) -> str:
    """Return a required string field."""
    raw_value = payload.get(key)
    if isinstance(raw_value, str):
        return raw_value
    raise FrontierMaterializationError(
        capsule_id="<unknown>",
        status=FrontierReconstructionStatus.SPILL_FORMAT_MISMATCH,
    )


def _required_int(payload: Mapping[str, object], key: str) -> int:
    """Return a required integer field."""
    raw_value = payload.get(key)
    if isinstance(raw_value, bool):
        _raise_format_error(payload)
    if isinstance(raw_value, int):
        return raw_value
    _raise_format_error(payload)


def _stack_values(
    payload: Mapping[str, object],
    key: str,
    value_table: Mapping[int, StackValue],
) -> list[StackValue]:
    """Return a primitive stack-value list."""
    return [
        _stack_value(raw_value, payload, value_table) for raw_value in _required_list(payload, key)
    ]


def _named_values(
    payload: Mapping[str, object],
    key: str,
    value_table: Mapping[int, StackValue],
) -> dict[str, StackValue]:
    """Return primitive named values from JSON pairs."""
    values: dict[str, StackValue] = {}
    for raw_pair in _required_list(payload, key):
        pair = _decoded_pair(raw_pair, payload)
        if len(pair) != 2:
            _raise_format_error(payload)
        raw_name, raw_value = pair
        if not isinstance(raw_name, str):
            _raise_format_error(payload)
        values[raw_name] = _stack_value(raw_value, payload, value_table)
    return values


def _memory_values(
    payload: Mapping[str, object],
    key: str,
    value_table: Mapping[int, StackValue],
) -> dict[int, StackValue]:
    """Return primitive memory values from JSON pairs."""
    values: dict[int, StackValue] = {}
    for raw_pair in _required_list(payload, key):
        pair = _decoded_pair(raw_pair, payload)
        if len(pair) != 2:
            _raise_format_error(payload)
        raw_address, raw_value = pair
        if isinstance(raw_address, bool) or not isinstance(raw_address, int):
            _raise_format_error(payload)
        values[raw_address] = _stack_value(raw_value, payload, value_table)
    return values


def _path_constraints(payload: Mapping[str, object], capsule_id: str) -> list[z3.BoolRef]:
    """Return Z3 path constraints decoded from an optional SMT2 payload."""
    smt2_payload = _optional_str(payload, "path_constraints_smt2")
    if smt2_payload is None:
        return []
    try:
        parsed_constraints = z3.parse_smt2_string(smt2_payload)
    except z3.Z3Exception as exc:
        raise FrontierMaterializationError(
            capsule_id=capsule_id,
            status=FrontierReconstructionStatus.SPILL_FORMAT_MISMATCH,
        ) from exc
    constraints = [constraint for constraint in parsed_constraints]
    if not all(isinstance(constraint, z3.BoolRef) for constraint in constraints):
        raise FrontierMaterializationError(
            capsule_id=capsule_id,
            status=FrontierReconstructionStatus.SPILL_FORMAT_MISMATCH,
        )
    return [cast("z3.BoolRef", constraint) for constraint in constraints]


def _int_sequence(payload: Mapping[str, object], key: str) -> tuple[int, ...]:
    """Return a tuple of integer fields."""
    values: list[int] = []
    for raw_value in _required_list(payload, key):
        if isinstance(raw_value, bool) or not isinstance(raw_value, int):
            _raise_format_error(payload)
        values.append(raw_value)
    return tuple(values)


def _str_sequence(payload: Mapping[str, object], key: str) -> tuple[str, ...]:
    """Return a tuple of string fields."""
    values: list[str] = []
    for raw_value in _required_list(payload, key):
        if not isinstance(raw_value, str):
            _raise_format_error(payload)
        values.append(raw_value)
    return tuple(values)


def _optional_str_tuple(payload: Mapping[str, object], key: str) -> tuple[str, ...] | None:
    """Return an optional string tuple field."""
    raw_value = payload.get(key)
    if raw_value is None:
        return None
    if not isinstance(raw_value, list):
        _raise_format_error(payload)
    values: list[str] = []
    for item in cast("list[object]", raw_value):
        if not isinstance(item, str):
            _raise_format_error(payload)
        values.append(item)
    return tuple(values)


def _optional_str(payload: Mapping[str, object], key: str) -> str | None:
    """Return an optional string field."""
    raw_value = payload.get(key)
    if raw_value is None or isinstance(raw_value, str):
        return raw_value
    _raise_format_error(payload)


def _stack_value(
    raw_value: object,
    payload: Mapping[str, object],
    value_table: Mapping[int, StackValue],
) -> StackValue:
    """Return a stack value from a validated value-table reference."""
    try:
        return decode_spill_value_ref(raw_value, value_table)
    except SpillValueDecodeError:
        _raise_format_error(payload)


def _optional_stack_value(
    payload: Mapping[str, object],
    key: str,
    value_table: Mapping[int, StackValue],
) -> StackValue | None:
    """Return an optional stack value from a value-table reference."""
    raw_value = payload.get(key)
    if raw_value is None:
        return None
    return _stack_value(raw_value, payload, value_table)


def _is_json_value(raw_value: object) -> bool:
    """Return whether ``raw_value`` came from JSON with supported structure."""
    if isinstance(raw_value, (bool, int, float, str)) or raw_value is None:
        return True
    if isinstance(raw_value, list):
        return all(_is_json_value(item) for item in cast("list[object]", raw_value))
    if isinstance(raw_value, dict):
        raw_mapping = cast("dict[object, object]", raw_value)
        return all(
            isinstance(key, str) and _is_json_value(value) for key, value in raw_mapping.items()
        )
    return False


def _required_list(payload: Mapping[str, object], key: str) -> list[object]:
    """Return a required JSON list field as objects."""
    raw_value = payload.get(key)
    if not isinstance(raw_value, list):
        _raise_format_error(payload)
    return cast("list[object]", raw_value)


def _decoded_pair(raw_pair: object, payload: Mapping[str, object]) -> list[object]:
    """Return a decoded JSON pair."""
    if not isinstance(raw_pair, list):
        _raise_format_error(payload)
    return cast("list[object]", raw_pair)


def _raise_format_error(payload: Mapping[str, object]) -> Never:
    """Raise a typed materialization error for malformed spill files."""
    raise FrontierMaterializationError(
        capsule_id=str(payload.get("capsule_id", "<unknown>")),
        status=FrontierReconstructionStatus.SPILL_FORMAT_MISMATCH,
    )
