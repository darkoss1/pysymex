from __future__ import annotations

import z3

from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.solver.engine.results import SolverResult
from pysymex.core.solver.unsat import extract_unsat_core
from pysymex.execution.scheduling.cegis import (
    BudgetVector,
    EvidenceAction,
    EvidenceActionKind,
    EvidenceCertificateKind,
    EvidenceOwner,
    EvidenceOutcomeKind,
    solver_unsat_core_outcome,
)


def _solver_action(action_id: str, *, capsule_id: str = "selected") -> EvidenceAction:
    return EvidenceAction(
        action_id=action_id,
        capsule_id=capsule_id,
        kind=EvidenceActionKind.TRY_UNSAT_CORE,
        owner=EvidenceOwner.SOLVER,
        required_budget=BudgetVector(path_budget=1),
        may_remove_work=True,
        requires_exact_evidence=True,
    )


def test_solver_unsat_core_outcome_builds_exact_certificate() -> None:
    """Solver-owned UNSAT core evidence can certify covered capsules."""
    action = _solver_action("solver-core")

    outcome = solver_unsat_core_outcome(
        action,
        SolverResult.unsat(),
        covered_capsule_ids=("selected", "covered-sibling"),
        core_indices=(0, 2),
    )

    assert outcome.kind is EvidenceOutcomeKind.EXACT_UNSAT
    assert outcome.certificate is not None
    assert outcome.certificate.kind is EvidenceCertificateKind.UNSAT_CORE
    assert outcome.certificate.core_indices == (0, 2)
    assert outcome.valid_removed_capsule_ids == ("selected", "covered-sibling")
    assert outcome.has_invalid_removal_attempt is False


def test_solver_unsat_core_outcome_accepts_real_z3_core_evidence() -> None:
    """Real project solver UNSAT plus extracted core can certify covered capsules."""
    x = z3.Int("cegis_real_unsat_core")
    constraints = [x > 0, x <= 0]
    solver_result = IncrementalSolver(use_cache=False).check_sat_result(constraints)
    core_result = extract_unsat_core(constraints)

    assert solver_result.is_unsat
    assert core_result is not None
    outcome = solver_unsat_core_outcome(
        _solver_action("solver-core"),
        solver_result,
        covered_capsule_ids=("selected",),
        core_indices=tuple(core_result.core_indices),
    )

    assert outcome.kind is EvidenceOutcomeKind.EXACT_UNSAT
    assert outcome.certificate is not None
    assert outcome.certificate.core_indices == tuple(core_result.core_indices)
    assert outcome.valid_removed_capsule_ids == ("selected",)


def test_solver_sat_outcome_cannot_remove_work() -> None:
    """SAT solver evidence is non-removing and produces no certificate."""
    outcome = solver_unsat_core_outcome(
        _solver_action("solver-sat"),
        SolverResult.sat(None),
        covered_capsule_ids=("selected", "sat-sibling"),
        core_indices=(0,),
    )

    assert outcome.kind is EvidenceOutcomeKind.SAT
    assert outcome.certificate is None
    assert outcome.valid_removed_capsule_ids == ()
    assert outcome.has_invalid_removal_attempt is False


def test_solver_unknown_outcome_cannot_remove_work() -> None:
    """Solver UNKNOWN remains inconclusive and cannot certify removals."""
    outcome = solver_unsat_core_outcome(
        _solver_action("solver-unknown"),
        SolverResult.unknown(),
        covered_capsule_ids=("selected",),
        core_indices=(0,),
    )

    assert outcome.kind is EvidenceOutcomeKind.SOLVER_UNKNOWN
    assert outcome.certificate is None
    assert outcome.valid_removed_capsule_ids == ()
    assert outcome.has_invalid_removal_attempt is False


def test_solver_timeout_outcome_cannot_remove_work() -> None:
    """Timeouts are explicit non-removing outcomes."""
    outcome = solver_unsat_core_outcome(
        _solver_action("solver-timeout"),
        SolverResult.unknown(),
        covered_capsule_ids=("selected",),
        core_indices=(0,),
        timed_out=True,
    )

    assert outcome.kind is EvidenceOutcomeKind.TIMEOUT
    assert outcome.certificate is None
    assert outcome.valid_removed_capsule_ids == ()
    assert outcome.has_invalid_removal_attempt is False


def test_solver_unsat_without_core_indices_cannot_certify_removal() -> None:
    """UNSAT without a concrete core is not enough for phase-0 removals."""
    outcome = solver_unsat_core_outcome(
        _solver_action("solver-coreless"),
        SolverResult.unsat(),
        covered_capsule_ids=("selected",),
        core_indices=(),
    )

    assert outcome.kind is EvidenceOutcomeKind.INCONCLUSIVE
    assert outcome.certificate is None
    assert outcome.valid_removed_capsule_ids == ()
    assert outcome.has_invalid_removal_attempt is False


def test_solver_unsat_without_selected_capsule_cannot_certify_removal() -> None:
    """An UNSAT-core certificate must cover the selected capsule."""
    outcome = solver_unsat_core_outcome(
        _solver_action("solver-core-missing-selected"),
        SolverResult.unsat(),
        covered_capsule_ids=("covered-sibling",),
        core_indices=(0,),
    )

    assert outcome.kind is EvidenceOutcomeKind.INCONCLUSIVE
    assert outcome.certificate is None
    assert outcome.valid_removed_capsule_ids == ()
    assert outcome.has_invalid_removal_attempt is False
