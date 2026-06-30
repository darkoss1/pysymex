"""Tests for POLAR shadow reconstruction checkpoints."""

from __future__ import annotations

import dis
from typing import cast

import z3

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.state.types import BlockInfo, CallFrame, wrap_cow_dict
from pysymex._internal.core.types.havoc import HavocValue
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.detectors.records import DeferredDetectorIssue
from pysymex._internal.execution.frontier.checkpoint.snapshot.record import FrontierStateSnapshot
from pysymex._internal.execution.frontier.checkpoint.snapshot.record import (
    FrontierStateSnapshot as FrontierStateSnapshotOwner,
)
from pysymex._internal.execution.frontier.checkpoints import (
    FrontierCheckpoint,
    FrontierReconstructionStatus,
    build_frontier_checkpoint,
)
from pysymex._internal.execution.frontier.obligations.digests import (
    capsule_matches_state,
    state_shadow_digest,
)
from pysymex._internal.execution.step.branch import build_state_key
from pysymex._internal.execution.step.fetch import fetch_instruction


def _instructions(source: str) -> list[dis.Instruction]:
    """Compile source into a stable instruction list for checkpoint dry-run tests."""
    return list(dis.get_instructions(compile(source, "<frontier-checkpoint-test>", "exec")))


def _state_with_symbolic_facts() -> VMState:
    value, constraint = SymbolicValue.symbolic("checkpoint_value")
    branch_condition = z3.Bool("checkpoint_branch")
    state = VMState(
        stack=[value],
        local_vars={"x": value},
        path_constraints=[constraint],
        pending_constraint_count=1,
        pc=11,
        path_id=7,
        depth=3,
    )
    state.record_branch(branch_condition, True, 11)
    return state


def test_frontier_checkpoint_snapshot_public_exports_point_to_direct_owner() -> None:
    assert FrontierStateSnapshot is FrontierStateSnapshotOwner


def test_frontier_checkpoint_reconstructs_exact_snapshot() -> None:
    """Checkpoint reconstruction returns a VMState matching the capsule digest."""
    state = _state_with_symbolic_facts()
    checkpoint = build_frontier_checkpoint(state, capsule_id="checkpoint-a")

    result = checkpoint.reconstruct()

    assert checkpoint.snapshot_matches_capsule()
    assert result.status is FrontierReconstructionStatus.EXACT
    assert result.reconstructed_state is not None
    assert result.reconstructed_state is not state
    assert result.reconstructed_state.path_id == state.path_id
    assert capsule_matches_state(checkpoint.capsule, result.reconstructed_state)
    assert result.expected_digest == result.actual_digest


def test_frontier_checkpoint_does_not_retain_full_vmstate_snapshot() -> None:
    """Checkpoint storage uses compact facts instead of a copied VMState."""
    state = _state_with_symbolic_facts()
    checkpoint = build_frontier_checkpoint(state, capsule_id="checkpoint-compact")
    snapshot = cast(
        "FrontierStateSnapshot",
        object.__getattribute__(checkpoint, "_snapshot"),
    )

    assert isinstance(snapshot, FrontierStateSnapshot)
    assert not isinstance(snapshot, VMState)
    assert snapshot.digest() == state_shadow_digest(state)


def test_frontier_checkpoint_isolated_from_source_state_mutation() -> None:
    """Later source-state mutation does not alter the stored reconstruction snapshot."""
    state = _state_with_symbolic_facts()
    checkpoint = build_frontier_checkpoint(state, capsule_id="checkpoint-isolated")
    source_digest = state_shadow_digest(state)
    state.pc = 99
    state.stack.append(SymbolicValue.symbolic("checkpoint_later")[0])
    state.local_vars["later"] = SymbolicValue.symbolic("checkpoint_local")[0]

    result = checkpoint.reconstruct()

    assert result.status is FrontierReconstructionStatus.EXACT
    assert result.reconstructed_state is not None
    assert state_shadow_digest(result.reconstructed_state) == source_digest
    assert result.reconstructed_state.pc == 11
    assert "later" not in result.reconstructed_state.local_vars


def test_frontier_checkpoint_preserves_dispatch_runtime_metadata() -> None:
    """Checkpoint reconstruction preserves metadata needed by future dispatch."""
    value, constraint = SymbolicValue.symbolic("checkpoint_runtime_value")
    instructions: list[object] = [object(), object()]
    previous_loop_state = VMState(pc=21, path_id=13)
    contract_frame = object()
    call_frame = CallFrame(
        "callee",
        2,
        wrap_cow_dict({"inner": value}),
        1,
        caller_stack=(value,),
        caller_instructions=instructions,
        protocol_method="__exit__",
    )
    state = VMState(
        stack=[value],
        local_vars={"x": value},
        global_vars={"g": value},
        path_constraints=[constraint],
        pc=1,
        block_stack=[BlockInfo("try", 0, 3, 2)],
        call_stack=[call_frame],
        contract_frames=[contract_frame],
        visited_pcs={0, 1},
        memory={3: value},
        path_id=17,
        depth=5,
        current_instructions=instructions,
        pending_constraint_count=1,
        last_inconclusive_feasibility_len=1,
        loop_iterations={1: 2, (1, 2): 3},
        loop_counters={4: 5},
        freed_vars={"gone"},
        prev_loop_states={1: previous_loop_state},
        open_resources=2,
    )
    state.pending_kw_names = ("left", "right")
    state.current_coro_id = "coro-1"
    state.awaitable_results[42] = value
    checkpoint = build_frontier_checkpoint(state, capsule_id="checkpoint-runtime")

    result = checkpoint.reconstruct()

    assert result.status is FrontierReconstructionStatus.EXACT
    assert result.reconstructed_state is not None
    reconstructed = result.reconstructed_state
    assert set(reconstructed.visited_pcs) == {0, 1}
    assert reconstructed.block_stack == [BlockInfo("try", 0, 3, 2)]
    assert reconstructed.call_stack == [call_frame]
    assert reconstructed.contract_frames == [contract_frame]
    assert reconstructed.current_instructions == instructions
    assert reconstructed.last_inconclusive_feasibility_len == 1
    assert dict(reconstructed.loop_iterations.items()) == {1: 2, (1, 2): 3}
    assert dict(reconstructed.loop_counters.items()) == {4: 5}
    assert set(reconstructed.freed_vars) == {"gone"}
    assert dict(reconstructed.prev_loop_states.items()) == {1: previous_loop_state}
    assert reconstructed.open_resources == 2
    assert reconstructed.pending_kw_names == ("left", "right")
    assert reconstructed.current_coro_id == "coro-1"
    assert reconstructed.awaitable_results == {42: value}


def test_frontier_checkpoint_preserves_deferred_detector_sidecars() -> None:
    """Detector sidecars survive checkpoint reconstruction as exact pending evidence."""
    issue = Issue(
        kind=IssueKind.DIVISION_BY_ZERO,
        message="possible zero divisor",
        pc=3,
        line_number=9,
    )
    changed_issue = Issue(
        kind=IssueKind.DIVISION_BY_ZERO,
        message="different zero-divisor evidence",
        pc=3,
        line_number=9,
    )
    deferred = DeferredDetectorIssue(issue, (123, 3, IssueKind.DIVISION_BY_ZERO))
    state = VMState(
        deferred_detector_issues=[deferred],
        pc=3,
        path_id=19,
        depth=2,
    )
    checkpoint = build_frontier_checkpoint(state, capsule_id="checkpoint-detector")
    changed_checkpoint = build_frontier_checkpoint(
        VMState(
            deferred_detector_issues=[
                DeferredDetectorIssue(
                    changed_issue,
                    (123, 3, IssueKind.DIVISION_BY_ZERO),
                ),
            ],
            pc=3,
            path_id=19,
            depth=2,
        ),
        capsule_id="checkpoint-detector-changed",
    )

    result = checkpoint.reconstruct()

    assert result.status is FrontierReconstructionStatus.EXACT
    assert result.reconstructed_state is not None
    assert result.reconstructed_state.deferred_detector_issues == [deferred]
    assert result.reconstructed_state.deferred_detector_issues[0].issue is issue
    assert result.reconstructed_state.deferred_detector_issues[0].site_key == (
        123,
        3,
        IssueKind.DIVISION_BY_ZERO,
    )
    assert checkpoint.snapshot_matches_capsule()
    assert checkpoint.snapshot.digest() != changed_checkpoint.snapshot.digest()


def test_frontier_checkpoint_digest_preserves_havoc_live_roots() -> None:
    """Checkpoint parity includes havoc precision-loss roots."""
    havoc_value, havoc_constraint = HavocValue.havoc("checkpoint_havoc_root")
    state = VMState(
        stack=[havoc_value],
        local_vars={"value": havoc_value},
        path_constraints=[havoc_constraint],
        pending_constraint_count=1,
        pc=23,
    )
    checkpoint = build_frontier_checkpoint(state, capsule_id="checkpoint-havoc")

    result = checkpoint.reconstruct()

    assert result.status is FrontierReconstructionStatus.EXACT
    assert result.reconstructed_state is not None
    assert result.actual_digest == state_shadow_digest(result.reconstructed_state)
    assert result.actual_digest == state_shadow_digest(state)


def test_frontier_checkpoint_shadow_dispatch_dry_run_matches_original_state() -> None:
    """Reconstructed states fetch and deduplicate like the queued original state."""
    value, constraint = SymbolicValue.symbolic("checkpoint_dry_run_value")
    root_instructions = _instructions("x = 1\ny = 2")
    active_instructions: list[object] = list(_instructions("z = 3\nw = 4"))
    state = VMState(
        stack=[value],
        local_vars={"x": value},
        path_constraints=[constraint],
        pc=1,
        visited_pcs={0},
        path_id=31,
        depth=4,
        current_instructions=active_instructions,
        pending_constraint_count=1,
    )
    checkpoint = build_frontier_checkpoint(state, capsule_id="checkpoint-dry-run")

    result = checkpoint.reconstruct()

    assert result.status is FrontierReconstructionStatus.EXACT
    assert result.reconstructed_state is not None
    original_instruction, original_active = fetch_instruction(state, root_instructions)
    reconstructed_instruction, reconstructed_active = fetch_instruction(
        result.reconstructed_state,
        root_instructions,
    )
    assert original_instruction == reconstructed_instruction
    assert original_active == reconstructed_active
    assert build_state_key(result.reconstructed_state) == build_state_key(state)


def test_frontier_checkpoint_rejects_snapshot_digest_mismatch() -> None:
    """Checkpoint reconstruction fails explicitly when the stored snapshot drifts."""
    state = _state_with_symbolic_facts()
    checkpoint = build_frontier_checkpoint(state, capsule_id="checkpoint-mismatch")
    assert isinstance(checkpoint, FrontierCheckpoint)
    snapshot = cast("FrontierStateSnapshot", object.__getattribute__(checkpoint, "_snapshot"))
    object.__setattr__(snapshot, "pc", 41)

    result = checkpoint.reconstruct()

    assert not checkpoint.snapshot_matches_capsule()
    assert result.status is FrontierReconstructionStatus.DIGEST_MISMATCH
    assert result.reconstructed_state is None
    assert result.expected_digest != result.actual_digest
