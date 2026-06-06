from __future__ import annotations

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.effects.events import WriteEvent, WriteKind
from pysymex.core.state.deferred import DeferredStateIssue
from pysymex.core.state.record import VMState
from pysymex.core.types.havoc import HavocValue
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.detectors import DeferredDetectorIssue
from pysymex.execution.frontier import (
    build_shadow_capsule,
    capsule_matches_state,
    capsule_semantic_digest,
    collect_frontier_telemetry,
    state_shadow_digest,
)


def test_build_shadow_capsule_captures_vmstate_without_mutating_it() -> None:
    """POLAR shadow capsules summarize runtime state without changing it."""
    stack_value, stack_constraint = SymbolicValue.symbolic("frontier_stack")
    local_value, local_constraint = SymbolicValue.symbolic("frontier_local")
    global_value, _ = SymbolicValue.symbolic("frontier_global")
    heap_value, _ = SymbolicValue.symbolic("frontier_heap")
    branch_condition = z3.Bool("frontier_branch")
    state = VMState(
        stack=[stack_value],
        local_vars={"local_b": local_value, "local_a": stack_value},
        global_vars={"global_z": global_value},
        path_constraints=[stack_constraint, local_constraint],
        pc=17,
        memory={4: heap_value},
        path_id=9,
        depth=3,
        deferred_detector_issues=[
            DeferredStateIssue(issue="deferred", site_key=("division", 17)),
        ],
        pending_constraint_count=2,
        write_events=[
            WriteEvent(WriteKind.GLOBAL, "global_z", 17, True, "STORE_GLOBAL"),
        ],
    )
    state.record_branch(branch_condition, True, 17)
    constraints_before = state.path_constraints.to_list()
    branch_len_before = len(state.branch_trace)

    capsule = build_shadow_capsule(state, capsule_id="capsule-a", parent_id="parent")

    assert capsule.capsule_id == "capsule-a"
    assert capsule.parent_id == "parent"
    assert capsule.path_id == 9
    assert capsule.depth == 3
    assert capsule.footprint.pc == 17
    assert capsule.footprint.state_structural_hash == state.hash_value()
    assert capsule.footprint.stack_depth == 1
    assert capsule.footprint.local_names == ("local_a", "local_b")
    assert capsule.footprint.global_names == ("global_z",)
    assert capsule.footprint.memory_cell_count == 1
    assert capsule.footprint.write_event_count == 1
    assert capsule.footprint.detector_obligation_count == 1
    assert capsule.constraint_atom_ids == tuple(
        sorted(constraint.hash() for constraint in constraints_before)
    )
    assert capsule.pending_constraint_count == 2
    assert capsule.branch_trace_length == branch_len_before
    assert capsule.estimated_resident_units == 10
    assert capsule_semantic_digest(capsule) == state_shadow_digest(state)
    assert capsule_matches_state(capsule, state)
    assert state.path_constraints.to_list() == constraints_before
    assert len(state.branch_trace) == branch_len_before


def test_capsule_digest_distinguishes_same_shape_different_values() -> None:
    """Duplicate-digest dominance requires structural state identity, not shape only."""
    left_value, _ = SymbolicValue.symbolic("frontier_digest_left")
    right_value, _ = SymbolicValue.symbolic("frontier_digest_right")
    left = build_shadow_capsule(
        VMState(stack=[left_value], pc=11, path_id=3, depth=2),
        capsule_id="left",
    )
    right = build_shadow_capsule(
        VMState(stack=[right_value], pc=11, path_id=3, depth=2),
        capsule_id="right",
    )

    assert left.footprint.stack_depth == right.footprint.stack_depth
    assert left.footprint.state_structural_hash != right.footprint.state_structural_hash
    assert capsule_semantic_digest(left) != capsule_semantic_digest(right)


def test_capsule_digest_distinguishes_same_site_different_detector_payload() -> None:
    """Detector parity keys prevent same-count evidence from collapsing together."""
    site_key = (101, 5, IssueKind.DIVISION_BY_ZERO)
    left_issue = Issue(
        kind=IssueKind.DIVISION_BY_ZERO,
        message="possible zero divisor",
        pc=5,
        line_number=12,
    )
    right_issue = Issue(
        kind=IssueKind.DIVISION_BY_ZERO,
        message="different zero-divisor evidence",
        pc=5,
        line_number=12,
    )
    left = build_shadow_capsule(
        VMState(
            deferred_detector_issues=[DeferredDetectorIssue(left_issue, site_key)],
            pc=5,
            path_id=3,
            depth=2,
        ),
        capsule_id="left-detector",
    )
    right = build_shadow_capsule(
        VMState(
            deferred_detector_issues=[DeferredDetectorIssue(right_issue, site_key)],
            pc=5,
            path_id=3,
            depth=2,
        ),
        capsule_id="right-detector",
    )

    assert left.footprint.detector_obligation_count == right.footprint.detector_obligation_count
    assert left.footprint.state_structural_hash == right.footprint.state_structural_hash
    assert left.footprint.detector_obligation_keys != right.footprint.detector_obligation_keys
    assert capsule_semantic_digest(left) != capsule_semantic_digest(right)


def test_capsule_digest_and_telemetry_preserve_havoc_live_roots() -> None:
    """Havoc precision loss is visible to POLAR parity and aggregate telemetry."""
    havoc_value, havoc_constraint = HavocValue.havoc("frontier_havoc_root")
    state = VMState(
        stack=[havoc_value],
        local_vars={"value": havoc_value},
        path_constraints=[havoc_constraint],
        pending_constraint_count=1,
        pc=13,
    )

    capsule = build_shadow_capsule(state, capsule_id="havoc")
    clean_capsule = build_shadow_capsule(
        VMState(
            stack=[1],
            local_vars={"value": 1},
            path_constraints=[havoc_constraint],
            pending_constraint_count=1,
            pc=13,
        ),
        capsule_id="clean",
    )
    telemetry = collect_frontier_telemetry([capsule, clean_capsule])

    assert capsule.footprint.unsupported_live_count == 0
    assert capsule.footprint.havoc_live_count == 2
    assert capsule_semantic_digest(capsule) == state_shadow_digest(state)
    assert capsule_semantic_digest(capsule) != capsule_semantic_digest(clean_capsule)
    assert telemetry.havoc_live_count == 2


def test_collect_frontier_telemetry_sums_shadow_capsules() -> None:
    """Frontier telemetry is an aggregate, not a pruning decision."""
    x = z3.Int("frontier_telemetry_x")
    first = build_shadow_capsule(
        VMState(path_constraints=[x > 0], pending_constraint_count=1, pc=1),
        capsule_id="first",
    )
    second = build_shadow_capsule(
        VMState(path_constraints=[x < 10, x != 7], pending_constraint_count=2, pc=2),
        capsule_id="second",
    )

    telemetry = collect_frontier_telemetry([first, second])

    assert telemetry.capsule_count == 2
    assert telemetry.constraint_atom_count == 3
    assert telemetry.pending_constraint_count == 3
    assert telemetry.estimated_resident_units == (
        first.estimated_resident_units + second.estimated_resident_units
    )
