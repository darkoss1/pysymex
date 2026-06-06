from __future__ import annotations

import z3

from pysymex.core.solver.engine.results import SolverResult
from pysymex.core.state.record import VMState
from pysymex.execution.frontier import build_frontier_checkpoint
from pysymex.execution.frontier.modes import FrontierRuntimeMode
from pysymex.execution.scheduling import create_path_manager
from pysymex.execution.scheduling.cegis import (
    BudgetVector,
    EvidenceAction,
    EvidenceActionKind,
    EvidenceCertificate,
    EvidenceCertificateKind,
    EvidenceOutcome,
    EvidenceOutcomeKind,
    EvidenceOwner,
    plan_evidence_application,
    solver_unsat_core_outcome,
)
from pysymex.execution.strategies.manager.types import ExplorationStrategy


def _solver_action(capsule_id: str) -> EvidenceAction:
    return EvidenceAction(
        action_id=f"{capsule_id}:unsat_core",
        capsule_id=capsule_id,
        kind=EvidenceActionKind.TRY_UNSAT_CORE,
        owner=EvidenceOwner.SOLVER,
        required_budget=BudgetVector(path_budget=1),
        may_remove_work=True,
        requires_exact_evidence=True,
    )


def test_plan_evidence_application_maps_reconstructed_capsule_to_live_state() -> None:
    """Shadow planning accepts exact reconstructed capsule evidence without mutating work."""
    x = z3.Int("cegis_application_x")
    state = VMState(pc=17, path_constraints=[x > 0], pending_constraint_count=1)
    checkpoint = build_frontier_checkpoint(state, capsule_id="path:0")
    reconstruction = checkpoint.reconstruct()
    outcome = solver_unsat_core_outcome(
        _solver_action(reconstruction.capsule_id),
        SolverResult.unsat(),
        covered_capsule_ids=(reconstruction.capsule_id,),
        core_indices=(0,),
    )

    assert reconstruction.is_exact
    plan = plan_evidence_application(
        outcome,
        live_state_ids=(0,),
        capsules_by_state_id={0: checkpoint.capsule},
    )

    assert plan.can_remove is True
    assert plan.removable_state_ids == (0,)
    assert plan.removable_capsule_ids == ("path:0",)


def test_plan_evidence_application_rejects_exact_outcome_without_certificate() -> None:
    """Exact outcome kind alone cannot identify removable live states."""
    checkpoint = build_frontier_checkpoint(VMState(pc=1), capsule_id="path:0")
    outcome = EvidenceOutcome(
        action=_solver_action("path:0"),
        kind=EvidenceOutcomeKind.EXACT_UNSAT,
        removed_capsule_ids=("path:0",),
    )

    plan = plan_evidence_application(
        outcome,
        live_state_ids=(0,),
        capsules_by_state_id={0: checkpoint.capsule},
    )

    assert plan.can_remove is False
    assert plan.invalid_removal_attempt is True
    assert plan.removable_state_ids == ()


def test_plan_evidence_application_rejects_solver_sat_unknown_and_timeout() -> None:
    """SAT, UNKNOWN, and timeout outcomes stay non-removing in the shadow harness."""
    checkpoint = build_frontier_checkpoint(VMState(pc=1), capsule_id="path:0")
    outcomes = (
        solver_unsat_core_outcome(
            _solver_action("path:0"),
            SolverResult.sat(None),
            covered_capsule_ids=("path:0",),
            core_indices=(0,),
        ),
        solver_unsat_core_outcome(
            _solver_action("path:0"),
            SolverResult.unknown(),
            covered_capsule_ids=("path:0",),
            core_indices=(0,),
        ),
        solver_unsat_core_outcome(
            _solver_action("path:0"),
            SolverResult.unknown(),
            covered_capsule_ids=("path:0",),
            core_indices=(0,),
            timed_out=True,
        ),
    )

    for outcome in outcomes:
        plan = plan_evidence_application(
            outcome,
            live_state_ids=(0,),
            capsules_by_state_id={0: checkpoint.capsule},
        )
        assert plan.can_remove is False
        assert plan.invalid_removal_attempt is False
        assert plan.removable_state_ids == ()


def test_plan_evidence_application_rejects_invalid_mixed_coverage() -> None:
    """Invalid mixed coverage cannot partially remove one certified live state."""
    first = build_frontier_checkpoint(VMState(pc=1), capsule_id="path:0")
    second = build_frontier_checkpoint(VMState(pc=2), capsule_id="path:1")
    outcome = EvidenceOutcome(
        action=_solver_action("path:0"),
        kind=EvidenceOutcomeKind.EXACT_UNSAT,
        removed_capsule_ids=("path:0", "path:1"),
        certificate=EvidenceCertificate(
            kind=EvidenceCertificateKind.UNSAT_CORE,
            subject_capsule_id="path:0",
            covered_capsule_ids=("path:0",),
        ),
    )

    plan = plan_evidence_application(
        outcome,
        live_state_ids=(0, 1),
        capsules_by_state_id={0: first.capsule, 1: second.capsule},
    )

    assert plan.can_remove is False
    assert plan.invalid_removal_attempt is True
    assert plan.removable_state_ids == ()


def test_plan_evidence_application_ignores_non_live_certified_capsules() -> None:
    """A valid certificate for a non-live capsule does not remove any queued state."""
    checkpoint = build_frontier_checkpoint(VMState(pc=1), capsule_id="path:0")
    outcome = solver_unsat_core_outcome(
        _solver_action("path:0"),
        SolverResult.unsat(),
        covered_capsule_ids=("path:0",),
        core_indices=(0,),
    )

    plan = plan_evidence_application(
        outcome,
        live_state_ids=(),
        capsules_by_state_id={0: checkpoint.capsule},
    )

    assert plan.can_remove is False
    assert plan.invalid_removal_attempt is False
    assert plan.removable_state_ids == ()


def test_valid_evidence_application_plan_does_not_apply_without_runtime_owner() -> None:
    """Dry-run no-false-prune evidence remains separate from runtime mutation."""
    checkpoint = build_frontier_checkpoint(VMState(pc=1), capsule_id="path:0")
    outcome = solver_unsat_core_outcome(
        _solver_action("path:0"),
        SolverResult.unsat(),
        covered_capsule_ids=("path:0",),
        core_indices=(0,),
    )
    plan = plan_evidence_application(
        outcome,
        live_state_ids=(0,),
        capsules_by_state_id={0: checkpoint.capsule},
    )

    assert plan.can_remove is True
    manager = create_path_manager(
        ExplorationStrategy.ADAPTIVE,
        frontier_runtime_mode=FrontierRuntimeMode.POLAR_CEGIS_RUNTIME,
    )
    assert manager.size() == 0
