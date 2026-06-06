from __future__ import annotations

from typing import cast

import z3

from pysymex.core.graph.cig import ConstraintInteractionGraph
from pysymex.core.solver.engine.results import SolverResult
from pysymex.core.state.record import VMState
from pysymex.execution.frontier import (
    FrontierRuntimeMode,
    materialize_frontier_queue_entry,
    state_shadow_digest,
)
from pysymex.execution.scheduling.cegis import (
    BudgetVector,
    EvidenceAction,
    EvidenceActionKind,
    EvidenceCertificate,
    EvidenceCertificateKind,
    EvidenceOutcome,
    EvidenceOutcomeKind,
    EvidenceOwner,
    solver_unsat_core_outcome,
)
from pysymex.execution.strategies.manager.path import AdaptivePathManager


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


def _manager_with_two_states() -> tuple[AdaptivePathManager, VMState, VMState]:
    manager = AdaptivePathManager(ConstraintInteractionGraph(), deterministic=True)
    removed_state = VMState(pc=1, pending_constraint_count=1)
    kept_state = VMState(pc=2, pending_constraint_count=1)
    manager.add_state(removed_state)
    manager.add_state(kept_state)
    return manager, removed_state, kept_state


def _generous_budget() -> BudgetVector:
    return BudgetVector(
        wall_time_ms=100.0,
        solver_time_ms=100.0,
        resident_units=100,
        reconstruction_units=100,
        path_budget=100,
    )


def _shadow_cegis_stats(manager: AdaptivePathManager) -> dict[str, object]:
    stats = manager.get_stats()
    return cast("dict[str, object]", stats["shadow_cegis"])


def _assert_resident_state_matches(selected: VMState | None, expected: VMState) -> None:
    assert selected is not None
    assert selected is expected
    assert state_shadow_digest(selected) == state_shadow_digest(expected)


def _queued_states(manager: AdaptivePathManager) -> tuple[VMState, ...]:
    return tuple(materialize_frontier_queue_entry(entry) for entry in manager.states.values())


def _queued_state_digests(manager: AdaptivePathManager) -> frozenset[object]:
    return frozenset(state_shadow_digest(state) for state in _queued_states(manager))


def test_apply_evidence_outcome_removes_certificate_covered_state() -> None:
    """Path-manager pruning now flows through CEGIS certificate outcomes."""
    manager, removed_state, kept_state = _manager_with_two_states()
    outcome = solver_unsat_core_outcome(
        _solver_action("path:0"),
        SolverResult.unsat(),
        covered_capsule_ids=("path:0",),
        core_indices=(0,),
    )

    killed = manager.apply_evidence_outcome(outcome)

    assert killed == 1
    assert manager.size() == 1
    stats = manager.get_stats()
    shadow_frontier = cast("dict[str, object]", stats["shadow_frontier"])
    assert shadow_frontier["capsule_count"] == 1
    assert shadow_frontier["checkpoint_count"] == 0
    shadow_cegis = _shadow_cegis_stats(manager)
    assert shadow_cegis["evidence_apply_count"] == 1
    assert shadow_cegis["evidence_apply_removed_state_count"] == 1
    assert shadow_cegis["evidence_apply_invalid_count"] == 0
    assert manager.get_next_state() is kept_state
    assert removed_state not in _queued_states(manager)


def test_preview_evidence_outcome_identifies_removal_without_mutating_frontier() -> None:
    """Preview exposes the certificate plan without removing queued work."""
    manager, removed_state, kept_state = _manager_with_two_states()
    outcome = solver_unsat_core_outcome(
        _solver_action("path:0"),
        SolverResult.unsat(),
        covered_capsule_ids=("path:0",),
        core_indices=(0,),
    )

    plan = manager.preview_evidence_outcome(outcome)

    assert plan.can_remove is True
    assert plan.removable_state_ids == (0,)
    assert plan.removable_capsule_ids == ("path:0",)
    assert manager.size() == 2
    assert removed_state in _queued_states(manager)
    assert kept_state in _queued_states(manager)
    shadow_cegis = _shadow_cegis_stats(manager)
    assert shadow_cegis["evidence_preview_count"] == 1
    assert shadow_cegis["evidence_preview_removable_state_count"] == 1
    assert shadow_cegis["evidence_preview_invalid_count"] == 0
    assert shadow_cegis["evidence_apply_count"] == 0


def test_preview_shadow_cegis_frontier_evaluates_owner_without_mutating_frontier() -> None:
    """Manager-level CEGIS preview can identify proof-backed work without pruning it."""
    manager = AdaptivePathManager(ConstraintInteractionGraph(), deterministic=True)
    x = z3.Int("manager_shadow_cegis_unsat")
    removed_state = VMState(
        pc=1,
        path_constraints=[x > 0, x <= 0],
        pending_constraint_count=2,
    )
    kept_state = VMState(pc=2)
    manager.add_state(removed_state)
    manager.add_state(kept_state)
    admission_stats = manager.get_stats()
    admission_frontier = cast("dict[str, object]", admission_stats["shadow_frontier"])
    assert admission_frontier["capsule_count"] == 0

    evaluation = manager.preview_shadow_cegis_frontier(_generous_budget())

    assert evaluation.has_decision is True
    assert evaluation.selected_state_id == 0
    assert evaluation.decision is not None
    assert evaluation.decision.selected_bid.action.kind is EvidenceActionKind.TRY_UNSAT_CORE
    assert evaluation.outcome is not None
    assert evaluation.outcome.kind is EvidenceOutcomeKind.EXACT_UNSAT
    assert evaluation.application_plan is not None
    assert evaluation.application_plan.can_remove is True
    assert evaluation.application_plan.removable_state_ids == (0,)
    assert manager.size() == 2
    assert removed_state in _queued_states(manager)
    assert kept_state in _queued_states(manager)
    preview_stats = manager.get_stats()
    preview_frontier = cast("dict[str, object]", preview_stats["shadow_frontier"])
    assert preview_frontier["capsule_count"] == 2
    shadow_cegis = _shadow_cegis_stats(manager)
    assert shadow_cegis["evidence_preview_count"] == 0
    assert shadow_cegis["evidence_apply_count"] == 0


def test_runtime_cegis_mode_keeps_unsat_state_explorable_after_native_selection() -> None:
    """Runtime native ordering may defer proof evidence but never consumes it implicitly."""
    manager = AdaptivePathManager(
        ConstraintInteractionGraph(),
        deterministic=True,
        frontier_runtime_mode=FrontierRuntimeMode.POLAR_CEGIS_RUNTIME,
    )
    x = z3.Int("manager_runtime_cegis_unsat")
    removed_state = VMState(
        pc=1,
        path_constraints=[x > 0, x <= 0],
        pending_constraint_count=2,
    )
    kept_state = VMState(pc=2)
    manager.add_state(removed_state)
    manager.add_state(kept_state)

    selected = manager.get_next_state()

    _assert_resident_state_matches(selected, kept_state)
    assert state_shadow_digest(removed_state) in _queued_state_digests(manager)
    later_selected = manager.get_next_state()
    _assert_resident_state_matches(later_selected, removed_state)
    shadow_cegis = _shadow_cegis_stats(manager)
    assert shadow_cegis["runtime_preview_count"] == 0
    assert shadow_cegis["runtime_removed_state_count"] == 0
    assert shadow_cegis["runtime_nonremoving_count"] == 0
    assert shadow_cegis["evidence_apply_count"] == 0
    assert shadow_cegis["evidence_apply_removed_state_count"] == 0
    assert shadow_cegis["runtime_execution_no_selection_count"] == 2


def test_runtime_cegis_mode_keeps_solver_sat_state_explorable() -> None:
    """Runtime mode never treats SAT owner evidence as removable work."""
    manager = AdaptivePathManager(
        ConstraintInteractionGraph(),
        deterministic=True,
        frontier_runtime_mode=FrontierRuntimeMode.POLAR_CEGIS_RUNTIME,
    )
    x = z3.Int("manager_runtime_cegis_sat")
    state = VMState(path_constraints=[x > 0], pending_constraint_count=1)
    manager.add_state(state)

    selected = manager.get_next_state()

    _assert_resident_state_matches(selected, state)
    shadow_cegis = _shadow_cegis_stats(manager)
    assert shadow_cegis["runtime_preview_count"] == 0
    assert shadow_cegis["runtime_removed_state_count"] == 0
    assert shadow_cegis["runtime_nonremoving_count"] == 0
    assert shadow_cegis["evidence_apply_count"] == 0
    assert shadow_cegis["runtime_execution_no_selection_count"] == 1


def test_preview_evidence_outcome_rejects_invalid_outcome_without_mutation() -> None:
    """Preview applies the same no-false-prune controls as live application."""
    manager, removed_state, kept_state = _manager_with_two_states()
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

    plan = manager.preview_evidence_outcome(outcome)

    assert plan.can_remove is False
    assert plan.invalid_removal_attempt is True
    assert plan.removable_state_ids == ()
    assert manager.size() == 2
    assert removed_state in _queued_states(manager)
    assert kept_state in _queued_states(manager)
    shadow_cegis = _shadow_cegis_stats(manager)
    assert shadow_cegis["evidence_preview_count"] == 1
    assert shadow_cegis["evidence_preview_removable_state_count"] == 0
    assert shadow_cegis["evidence_preview_invalid_count"] == 1
    assert shadow_cegis["evidence_apply_count"] == 0


def test_apply_evidence_outcome_rejects_exact_outcome_without_certificate() -> None:
    """The removed raw-core fallback cannot prune through exact kind alone."""
    manager, removed_state, kept_state = _manager_with_two_states()
    outcome = EvidenceOutcome(
        action=_solver_action("path:0"),
        kind=EvidenceOutcomeKind.EXACT_UNSAT,
        removed_capsule_ids=("path:0",),
    )

    killed = manager.apply_evidence_outcome(outcome)

    assert killed == 0
    assert manager.size() == 2
    assert removed_state in _queued_states(manager)
    assert kept_state in _queued_states(manager)
    shadow_cegis = _shadow_cegis_stats(manager)
    assert shadow_cegis["evidence_apply_count"] == 1
    assert shadow_cegis["evidence_apply_removed_state_count"] == 0
    assert shadow_cegis["evidence_apply_invalid_count"] == 1


def test_apply_evidence_outcome_rejects_solver_sat() -> None:
    """SAT solver evidence cannot remove frontier work."""
    manager, removed_state, kept_state = _manager_with_two_states()
    outcome = solver_unsat_core_outcome(
        _solver_action("path:0"),
        SolverResult.sat(None),
        covered_capsule_ids=("path:0",),
        core_indices=(0,),
    )

    killed = manager.apply_evidence_outcome(outcome)

    assert killed == 0
    assert manager.size() == 2
    assert removed_state in _queued_states(manager)
    assert kept_state in _queued_states(manager)


def test_apply_evidence_outcome_rejects_invalid_partial_removal() -> None:
    """Invalid mixed certificate coverage does not partly prune live states."""
    manager, removed_state, kept_state = _manager_with_two_states()
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

    killed = manager.apply_evidence_outcome(outcome)

    assert killed == 0
    assert manager.size() == 2
    assert removed_state in _queued_states(manager)
    assert kept_state in _queued_states(manager)
