from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

import pytest
import z3

import pysymex._internal.execution.frontier.spill.decode.constraints as spill_decode_constraints
import pysymex._internal.execution.frontier.spill.fields.decode as decode_fields
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.frontier.checkpoints import FrontierReconstructionStatus
from pysymex._internal.execution.frontier.entries import (
    FrontierMaterializationError,
    FrontierQueueEntry,
)
from pysymex._internal.execution.frontier.modes import FrontierRuntimeMode
from pysymex._internal.execution.frontier.spill.codec.digests import spill_payload_integrity_digest
from pysymex._internal.execution.frontier.spill.decode.entry import realize_spilled_frontier_entry
from pysymex._internal.execution.frontier.spill.decode.entry import (
    realize_spilled_frontier_entry as materialize_spilled_frontier_entry_owner,
)
from pysymex._internal.execution.frontier.spill.policy import FrontierSpillPolicy
from pysymex._internal.execution.frontier.store.core import FrontierWorkStore


def _filesystem_spill_policy(tmp_path: Path) -> FrontierSpillPolicy:
    return FrontierSpillPolicy(
        filesystem_spill_enabled=True,
        spill_directory=tmp_path / "frontier-spill",
    )


def _spilled_payload(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    state = VMState(
        stack=[1],
        local_vars={"x": 1},
        global_vars={"g": 2},
        memory={3: "value"},
        pc=5,
        visited_pcs={1, 5},
        path_id=7,
        depth=2,
        freed_vars={"tmp"},
    )
    state.pending_kw_names = ("name",)
    state.current_coro_id = "coro"
    store.add_state(0, state)
    decision = store.request_spill(0, _filesystem_spill_policy(tmp_path))
    assert decision.spill_path is not None
    payload = json.loads(decision.spill_path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return decision.spill_path, cast("dict[str, object]", payload)


def _write_payload(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def _refresh_spill_integrity(payload: dict[str, object]) -> None:
    payload["expected_spill_digest"] = spill_payload_integrity_digest(payload)


def _assert_materialization_format_mismatch(path: Path) -> None:
    entry = FrontierQueueEntry(spilled_checkpoint_path=path)
    with pytest.raises(FrontierMaterializationError) as exc_info:
        realize_spilled_frontier_entry(entry)
    assert exc_info.value.status is FrontierReconstructionStatus.SPILL_FORMAT_MISMATCH


def test_spill_decode_public_export_points_to_entry_owner() -> None:
    """Package-level decode export stays wired to the file-loading owner."""
    assert realize_spilled_frontier_entry is materialize_spilled_frontier_entry_owner


def test_materialize_spilled_frontier_entry_requires_spilled_entry() -> None:
    """Spill materialization rejects resident entries."""
    with pytest.raises(ValueError, match="not spilled"):
        realize_spilled_frontier_entry(FrontierQueueEntry(state=VMState(pc=1)))


def test_materialize_spilled_frontier_entry_reports_missing_files(tmp_path: Path) -> None:
    """Missing spill files fail closed as typed format mismatches."""
    _assert_materialization_format_mismatch(tmp_path / "missing.json")


def test_materialize_spilled_frontier_entry_rejects_non_object_payload(tmp_path: Path) -> None:
    """Decoded JSON must be a string-keyed object."""
    spill_path = tmp_path / "payload.json"
    spill_path.write_text("[]", encoding="utf-8")

    _assert_materialization_format_mismatch(spill_path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("version", 0),
        ("capsule_id", 7),
        ("stack", "bad"),
        ("local_vars", [["x"]]),
        ("local_vars", [[1, {"$ref": 0}]]),
        ("global_vars", ["bad"]),
        ("memory", [[1]]),
        ("memory", [[True, {"$ref": 0}]]),
        ("path_constraints_smt2", "(assert true"),
        ("pc", True),
        ("path_id", None),
        ("visited_pcs", [True]),
        ("deferred_detector_issues", "bad"),
        ("block_stack", "bad"),
        ("freed_vars", [1]),
        ("pending_kw_names", "bad"),
        ("pending_kw_names", [1]),
        ("current_coro_id", 3),
    ],
)
def test_materialize_spilled_frontier_entry_rejects_malformed_fields(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    """Corrupt spill-file fields never reconstruct partial VM state."""
    spill_path, payload = _spilled_payload(tmp_path)
    payload[field] = value
    _refresh_spill_integrity(payload)
    _write_payload(spill_path, payload)

    _assert_materialization_format_mismatch(spill_path)


def test_materialize_spilled_frontier_entry_rejects_digest_mismatch(tmp_path: Path) -> None:
    """Digest mismatches prove the spill payload is not exact."""
    spill_path, payload = _spilled_payload(tmp_path)
    payload["expected_digest"] = "wrong"
    _write_payload(spill_path, payload)

    entry = FrontierQueueEntry(spilled_checkpoint_path=spill_path)
    with pytest.raises(FrontierMaterializationError) as exc_info:
        realize_spilled_frontier_entry(entry)

    assert exc_info.value.status is FrontierReconstructionStatus.DIGEST_MISMATCH


def test_materialize_spilled_frontier_entry_rejects_stale_spill_integrity(
    tmp_path: Path,
) -> None:
    """Spill-local integrity catches valid mutations outside capsule digest fields."""
    spill_path, payload = _spilled_payload(tmp_path)
    payload["pending_kw_names"] = ["changed"]
    _write_payload(spill_path, payload)

    _assert_materialization_format_mismatch(spill_path)


def test_spill_decode_object_payload_rejects_non_string_mapping_keys() -> None:
    """Decoded payload helpers reject Python mappings that JSON should not produce."""
    object_payload = cast(
        "Callable[[object], Mapping[str, object] | None]",
        decode_fields.object_payload,
    )

    assert object_payload({1: "bad"}) is None


@pytest.mark.parametrize(
    "bad_digest",
    [
        {1: "bad"},
        object(),
    ],
)
def test_spill_decode_required_json_value_rejects_non_json_values(
    bad_digest: object,
) -> None:
    """Digest payload validation rejects non-JSON Python object shapes."""
    payload: dict[str, object] = {
        "capsule_id": "capsule",
        "expected_digest": bad_digest,
    }
    required_json_value = cast(
        "Callable[[Mapping[str, object], str], object]",
        decode_fields.required_json_value,
    )

    with pytest.raises(FrontierMaterializationError) as exc_info:
        required_json_value(payload, "expected_digest")

    assert exc_info.value.status is FrontierReconstructionStatus.SPILL_FORMAT_MISMATCH


def test_materialize_spilled_frontier_entry_rejects_non_bool_smt2_results(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Parsed SMT2 payloads must reconstruct only Boolean path constraints."""
    spill_path, payload = _spilled_payload(tmp_path)
    payload["path_constraints_smt2"] = "(assert true)"
    _refresh_spill_integrity(payload)
    _write_payload(spill_path, payload)

    def parse_non_bool_constraints(_payload: str) -> list[z3.ArithRef]:
        return [z3.IntVal(1)]

    monkeypatch.setattr(
        spill_decode_constraints.z3, "parse_smt2_string", parse_non_bool_constraints
    )

    _assert_materialization_format_mismatch(spill_path)
