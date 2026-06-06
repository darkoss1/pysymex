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

"""Deterministic JSON/SMT2 encoding for safe frontier checkpoint spill files."""

from __future__ import annotations

import json
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from typing import cast

import z3

from pysymex.execution.frontier.checkpoints import FrontierCheckpoint
from pysymex.execution.frontier.entries import FrontierQueueEntry
from pysymex.execution.frontier.spill.detectors import detector_issues_payload
from pysymex.execution.frontier.spill.instructions import current_instructions_payload
from pysymex.execution.frontier.spill.metadata import (
    block_stack_payload,
    loop_counters_payload,
    loop_iterations_payload,
    write_events_payload,
)
from pysymex.execution.frontier.spill.values import (
    JsonObject,
    JsonValue,
    SpillValueEncoder,
)

__all__ = [
    "JsonObject",
    "JsonValue",
    "SPILL_FORMAT_VERSION",
    "checkpoint_spill_payload",
    "delete_spilled_frontier_entry",
    "json_digest_value",
    "spill_payload_integrity_digest",
    "spill_path",
    "write_spill_payload",
]

SPILL_FORMAT_VERSION = 3

_EXPECTED_DIGEST_KEY = "expected_digest"
_EXPECTED_SPILL_DIGEST_KEY = "expected_spill_digest"
_SPILL_INTEGRITY_EXCLUDED_KEYS = frozenset(
    {
        _EXPECTED_DIGEST_KEY,
        _EXPECTED_SPILL_DIGEST_KEY,
    }
)


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
    if (
        snapshot.active_exception is not None
        and active_exception is None
        or snapshot.pending_reraise_exception is not None
        and pending_reraise_exception is None
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
    constraints_smt2 = _constraints_payload(snapshot.path_constraints)
    if isinstance(constraints_smt2, _UnsupportedSentinel):
        return None

    pending_kw_names: list[JsonValue] | None = (
        list(snapshot.pending_kw_names) if snapshot.pending_kw_names is not None else None
    )
    visited_pcs: list[JsonValue] = [visited_pc for visited_pc in sorted(snapshot.visited_pcs)]
    freed_vars: list[JsonValue] = [freed_var for freed_var in sorted(snapshot.freed_vars)]
    payload: JsonObject = {
        "version": SPILL_FORMAT_VERSION,
        "capsule_id": checkpoint.capsule.capsule_id,
        _EXPECTED_DIGEST_KEY: json_digest_value(snapshot.digest()),
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
    payload[_EXPECTED_SPILL_DIGEST_KEY] = spill_payload_integrity_digest(payload)
    return payload


def delete_spilled_frontier_entry(entry: FrontierQueueEntry) -> None:
    """Remove the spill file for ``entry`` when it owns one."""
    spill_file = entry.spilled_checkpoint_path
    if spill_file is not None:
        spill_file.unlink(missing_ok=True)


def spill_path(root: Path, *, state_id: int, capsule_id: str) -> Path:
    """Return the deterministic spill path for one live state ID."""
    root.mkdir(parents=True, exist_ok=True)
    if not root.is_dir():
        msg = "frontier spill root is not a directory"
        raise OSError(msg)
    capsule_hash = sha256(capsule_id.encode("utf-8")).hexdigest()[:16]
    candidate = (root / f"frontier-{state_id}-{capsule_hash}.json").resolve(strict=False)
    if not candidate.is_relative_to(root):
        msg = "frontier spill path escaped configured root"
        raise OSError(msg)
    return candidate


def write_spill_payload(spill_file: Path, payload: JsonObject) -> None:
    """Write one spill payload atomically within the spill directory."""
    temporary_path = spill_file.with_name(f"{spill_file.name}.tmp")
    with temporary_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
    temporary_path.replace(spill_file)


def json_digest_value(value: object) -> JsonValue:
    """Convert digest tuples into deterministic JSON values."""
    if isinstance(value, (bool, int, float, str)) or value is None:
        return value
    if isinstance(value, tuple):
        return [json_digest_value(item) for item in cast("tuple[object, ...]", value)]
    if isinstance(value, list):
        return [json_digest_value(item) for item in cast("list[object]", value)]
    msg = f"unsupported digest value for frontier spill: {type(value).__name__}"
    raise TypeError(msg)


def spill_payload_integrity_digest(payload: Mapping[str, object]) -> str:
    """Return a cold-path digest for spill payload fields outside capsule truth.

    The capsule digest remains the semantic proof boundary. This integrity digest
    is a deterministic fail-closed guard against accidental spill-file mutation
    for serialized runtime fields that are reconstructed before the capsule
    digest is rechecked.
    """
    digest_payload = {
        key: value for key, value in payload.items() if key not in _SPILL_INTEGRITY_EXCLUDED_KEYS
    }
    canonical = json.dumps(digest_payload, sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode("utf-8")).hexdigest()


def _constraints_payload(
    constraints: tuple[z3.BoolRef, ...],
) -> str | None | "_UnsupportedSentinel":
    """Encode solver constraints as deterministic SMT2 assertions."""
    if not constraints:
        return None
    try:
        solver = z3.Solver()
        solver.add(*constraints)
        return solver.to_smt2()
    except z3.Z3Exception:
        return _UNSUPPORTED


class _UnsupportedSentinel:
    """Sentinel for values that must not cross the spill boundary."""


_UNSUPPORTED = _UnsupportedSentinel()
