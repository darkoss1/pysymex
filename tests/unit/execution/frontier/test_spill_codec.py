from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
import z3

import pysymex._internal.execution.frontier.spill.codec.constraints as spill_codec_constraints
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.frontier.checkpoints import (
    FrontierCheckpoint,
    build_frontier_checkpoint,
)
from pysymex._internal.execution.frontier.entries import FrontierQueueEntry
from pysymex._internal.execution.frontier.spill.codec.digests import (
    json_digest_value,
    spill_payload_integrity_digest,
)
from pysymex._internal.execution.frontier.spill.codec.digests import (
    json_digest_value as direct_json_digest_value,
)
from pysymex._internal.execution.frontier.spill.codec.digests import (
    spill_payload_integrity_digest as direct_spill_payload_integrity_digest,
)
from pysymex._internal.execution.frontier.spill.codec.files import (
    delete_spilled_frontier_entry,
    spill_path,
    write_spill_payload,
)
from pysymex._internal.execution.frontier.spill.codec.files import (
    delete_spilled_frontier_entry as direct_delete_spilled_frontier_entry,
)
from pysymex._internal.execution.frontier.spill.codec.files import (
    spill_path as direct_spill_path,
)
from pysymex._internal.execution.frontier.spill.codec.files import (
    write_spill_payload as direct_write_spill_payload,
)
from pysymex._internal.execution.frontier.spill.codec.payloads import (
    SPILL_FORMAT_VERSION,
    checkpoint_spill_payload,
)
from pysymex._internal.execution.frontier.spill.codec.payloads import (
    SPILL_FORMAT_VERSION as DIRECT_SPILL_FORMAT_VERSION,
)
from pysymex._internal.execution.frontier.spill.codec.payloads import (
    checkpoint_spill_payload as direct_checkpoint_spill_payload,
)


def test_spill_codec_exports_use_direct_owners() -> None:
    """Package-level codec exports stay wired to direct owners."""
    assert SPILL_FORMAT_VERSION == DIRECT_SPILL_FORMAT_VERSION
    assert checkpoint_spill_payload is direct_checkpoint_spill_payload
    assert delete_spilled_frontier_entry is direct_delete_spilled_frontier_entry
    assert json_digest_value is direct_json_digest_value
    assert spill_payload_integrity_digest is direct_spill_payload_integrity_digest
    assert spill_path is direct_spill_path
    assert write_spill_payload is direct_write_spill_payload


def test_checkpoint_spill_payload_rejects_stale_snapshots() -> None:
    """Checkpoint payloads are spill-safe only when capsule and snapshot still match."""
    checkpoint = build_frontier_checkpoint(VMState(pc=1, path_id=1))
    stale_snapshot = build_frontier_checkpoint(VMState(pc=2, path_id=1)).snapshot
    stale_checkpoint = FrontierCheckpoint(checkpoint.capsule, stale_snapshot)

    assert checkpoint_spill_payload(stale_checkpoint) is None


def test_checkpoint_spill_payload_records_cold_integrity_digest() -> None:
    """Generated spill payloads carry a local digest without changing capsule truth."""
    payload = checkpoint_spill_payload(build_frontier_checkpoint(VMState(pc=1, path_id=1)))
    assert payload is not None

    assert payload["version"] == SPILL_FORMAT_VERSION
    assert payload["expected_spill_digest"] == spill_payload_integrity_digest(payload)


def test_checkpoint_spill_payload_rejects_unsupported_runtime_metadata() -> None:
    """Runtime-only metadata stays resident until it has an exact spill contract."""
    state = VMState(
        current_instructions=[object()],
        pc=1,
        path_id=2,
    )

    assert checkpoint_spill_payload(build_frontier_checkpoint(state)) is None


def test_checkpoint_spill_payload_rejects_branch_traces() -> None:
    """Branch traces remain denied until their exact digest contract is widened."""
    state = VMState(pc=1, path_id=2)
    state.record_branch(z3.Bool("spill_branch_trace_denial"), True, 1)

    assert checkpoint_spill_payload(build_frontier_checkpoint(state)) is None


def test_checkpoint_spill_payload_rejects_metadata_encoder_denials() -> None:
    """Metadata helper denials propagate as unsupported checkpoint payloads."""
    state = VMState(
        loop_counters={cast("int", True): 1},
        pc=1,
        path_id=3,
    )

    assert checkpoint_spill_payload(build_frontier_checkpoint(state)) is None


def test_checkpoint_spill_payload_rejects_smt2_serialization_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Solver serialization failures fail closed instead of dropping constraints."""

    class RaisingSolver:
        def add(self, *_constraints: z3.BoolRef) -> None:
            return None

        def to_smt2(self) -> str:
            raise z3.Z3Exception("serialization failed")

    monkeypatch.setattr(spill_codec_constraints.z3, "Solver", RaisingSolver)
    symbol = z3.Bool("spill_codec_smt2_failure")
    state = VMState(
        path_constraints=[symbol],
        pending_constraint_count=1,
        pc=1,
        path_id=4,
    )

    assert checkpoint_spill_payload(build_frontier_checkpoint(state)) is None


def test_delete_spilled_frontier_entry_ignores_resident_entries() -> None:
    """Cleanup is a no-op for resident entries without spill files."""
    delete_spilled_frontier_entry(FrontierQueueEntry(state=VMState(pc=1)))


def test_spill_path_rejects_roots_that_are_not_directories(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Spill root validation fails closed when directory creation is ineffective."""

    def noop_mkdir(
        self: Path,
        *_args: object,
        **_kwargs: object,
    ) -> None:
        return None

    def false_is_dir(self: Path) -> bool:
        return False

    monkeypatch.setattr(Path, "mkdir", noop_mkdir)
    monkeypatch.setattr(Path, "is_dir", false_is_dir)

    with pytest.raises(OSError, match="not a directory"):
        spill_path(tmp_path / "spill", state_id=1, capsule_id="capsule")


def test_spill_path_rejects_unresolved_roots_that_escape(tmp_path: Path) -> None:
    """Spill paths must remain under the exact configured root."""
    unresolved_root = tmp_path / "spill" / ".." / "spill"

    with pytest.raises(OSError, match="escaped"):
        spill_path(unresolved_root, state_id=1, capsule_id="capsule")


def test_json_digest_value_handles_lists_and_rejects_unknown_objects() -> None:
    """Digest JSON conversion is deterministic and narrow."""
    assert json_digest_value([("nested", [1, None])]) == [["nested", [1, None]]]

    with pytest.raises(TypeError, match="unsupported digest value"):
        json_digest_value(object())
