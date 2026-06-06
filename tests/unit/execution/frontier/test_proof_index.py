from __future__ import annotations

from typing import cast

import z3

from pysymex.core.state.record import VMState
from pysymex.execution.frontier import (
    FrontierStateSnapshot,
    build_frontier_checkpoint,
    exact_unsat_core_coverage,
)


def test_exact_unsat_core_coverage_matches_only_core_supersets() -> None:
    """UNSAT-core reuse covers live checkpoints containing every exact core AST."""
    x = z3.Int("frontier_proof_index_x")
    positive = x > 0
    nonpositive = x <= 0
    subject = build_frontier_checkpoint(
        VMState(path_constraints=[positive, nonpositive], pending_constraint_count=2),
        capsule_id="path:0",
    )
    duplicate = build_frontier_checkpoint(
        VMState(path_constraints=[positive, nonpositive], pending_constraint_count=2),
        capsule_id="path:1",
    )
    sat_sibling = build_frontier_checkpoint(
        VMState(path_constraints=[positive], pending_constraint_count=1),
        capsule_id="path:2",
    )

    coverage = exact_unsat_core_coverage(
        subject,
        (subject, duplicate, sat_sibling),
        core_indices=(0, 1),
    )

    assert coverage.covered_capsule_ids == ("path:0", "path:1")
    assert coverage.core_constraint_count == 2


def test_exact_unsat_core_coverage_rejects_invalid_core_indices() -> None:
    """Malformed core indices cannot certify frontier coverage."""
    x = z3.Int("frontier_proof_index_invalid")
    subject = build_frontier_checkpoint(
        VMState(path_constraints=[x > 0], pending_constraint_count=1),
        capsule_id="path:0",
    )

    coverage = exact_unsat_core_coverage(subject, (subject,), core_indices=(3,))

    assert coverage.covered_capsule_ids == ()
    assert coverage.core_constraint_count == 0


def test_exact_unsat_core_coverage_skips_mismatched_checkpoints() -> None:
    """Checkpoint drift remains non-covering even when constraints match."""
    x = z3.Int("frontier_proof_index_mismatch")
    positive = x > 0
    nonpositive = x <= 0
    subject = build_frontier_checkpoint(
        VMState(path_constraints=[positive, nonpositive], pending_constraint_count=2),
        capsule_id="path:0",
    )
    candidate = build_frontier_checkpoint(
        VMState(path_constraints=[positive, nonpositive], pending_constraint_count=2),
        capsule_id="path:1",
    )
    snapshot = cast("FrontierStateSnapshot", object.__getattribute__(candidate, "_snapshot"))
    object.__setattr__(snapshot, "pc", 99)

    coverage = exact_unsat_core_coverage(subject, (subject, candidate), core_indices=(0, 1))

    assert coverage.covered_capsule_ids == ("path:0",)
