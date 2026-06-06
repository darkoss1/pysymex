from __future__ import annotations

from typing import cast

from pytest import MonkeyPatch
import z3

from pysymex.core.solver.engine.results import SolverResult
from pysymex.core.state.deferred import DeferredStateIssue
from pysymex.core.state.record import VMState
from pysymex.execution.frontier import FrontierRuntimeMode, FrontierWorkStore, ObligationCapsule
from pysymex.execution.frontier.store import FrontierRuntimeFeatures
from pysymex.execution.scheduling.cegis import (
    BudgetVector,
    CegisRuntimeController,
    EvidenceAction,
    EvidenceActionKind,
    EvidenceApplicationPlan,
    EvidenceOwner,
    ShadowDecisionEvaluation,
    solver_unsat_core_outcome,
)


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


def test_cegis_runtime_controller_previews_without_mutating_frontier() -> None:
    """Preview accounting is owned by CEGIS while queue mutation remains separate."""
    frontier = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_SHADOW)
    frontier.add_state(0, VMState(pc=1, pending_constraint_count=1))
    controller = CegisRuntimeController()
    outcome = solver_unsat_core_outcome(
        _solver_action("path:0"),
        SolverResult.unsat(),
        covered_capsule_ids=("path:0",),
        core_indices=(0,),
    )

    plan = controller.preview_evidence_outcome(frontier, outcome)

    assert plan.can_remove is True
    assert len(frontier) == 1
    stats = controller.collect_stats(frontier, enabled=True)
    assert stats.evidence_preview_count == 1
    assert stats.evidence_preview_removable_state_count == 1
    assert stats.evidence_apply_count == 0


def test_cegis_runtime_controller_applies_only_certificate_backed_removal() -> None:
    """Exact certificate outcomes can remove live work through the frontier store."""
    frontier = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_SHADOW)
    frontier.add_state(0, VMState(pc=1, pending_constraint_count=1))
    frontier.add_state(1, VMState(pc=2))
    controller = CegisRuntimeController()
    outcome = solver_unsat_core_outcome(
        _solver_action("path:0"),
        SolverResult.unsat(),
        covered_capsule_ids=("path:0",),
        core_indices=(0,),
    )

    removed = controller.apply_evidence_outcome(frontier, outcome)

    assert removed == 1
    assert tuple(frontier.live_state_ids) == (1,)
    stats = controller.collect_stats(frontier, enabled=True)
    assert stats.evidence_apply_count == 1
    assert stats.evidence_apply_removed_state_count == 1
    assert stats.evidence_apply_invalid_count == 0


def test_runtime_proof_loop_removes_only_exact_unsat_when_limit_enabled(
    monkeypatch: MonkeyPatch,
) -> None:
    """The disabled automatic proof loop removes work only after exact UNSAT evidence."""
    monkeypatch.setattr(CegisRuntimeController, "_RUNTIME_CEGIS_PROOF_FRONTIER_LIMIT", 4)
    frontier = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    x = z3.Int("cegis_runtime_auto_unsat")
    frontier.add_state(
        0,
        VMState(path_constraints=[x > 0, x <= 0], pending_constraint_count=2),
    )
    controller = CegisRuntimeController()

    controller.apply_runtime_evidence(frontier)

    assert len(frontier) == 0
    stats = controller.collect_stats(frontier, enabled=True)
    assert stats.runtime_preview_count == 1
    assert stats.runtime_removed_state_count == 1
    assert stats.runtime_nonremoving_count == 0
    assert stats.evidence_apply_removed_state_count == 1


def test_runtime_proof_loop_keeps_sat_work_when_limit_enabled(
    monkeypatch: MonkeyPatch,
) -> None:
    """SAT owner evidence remains non-removing even if runtime proof preview is enabled."""
    monkeypatch.setattr(CegisRuntimeController, "_RUNTIME_CEGIS_PROOF_FRONTIER_LIMIT", 4)
    frontier = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    x = z3.Int("cegis_runtime_auto_sat")
    frontier.add_state(0, VMState(path_constraints=[x > 0], pending_constraint_count=1))
    controller = CegisRuntimeController()

    controller.apply_runtime_evidence(frontier)

    assert len(frontier) == 1
    stats = controller.collect_stats(frontier, enabled=True)
    assert stats.runtime_preview_count == 1
    assert stats.runtime_removed_state_count == 0
    assert stats.runtime_nonremoving_count == 1
    assert stats.evidence_apply_removed_state_count == 0


def test_runtime_proof_loop_counts_zero_removal_after_positive_preview(
    monkeypatch: MonkeyPatch,
) -> None:
    """A positive preview that cannot mutate live work is recorded as non-removing."""
    monkeypatch.setattr(CegisRuntimeController, "_RUNTIME_CEGIS_PROOF_FRONTIER_LIMIT", 4)
    frontier = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    frontier.add_state(0, VMState(pc=1))
    controller = CegisRuntimeController()
    outcome = solver_unsat_core_outcome(
        _solver_action("path:0"),
        SolverResult.unsat(),
        covered_capsule_ids=("path:0",),
        core_indices=(0,),
    )
    plan = EvidenceApplicationPlan(
        outcome=outcome,
        removable_state_ids=(0,),
        removable_capsule_ids=("path:0",),
        invalid_removal_attempt=False,
        explanation="unit positive preview",
    )

    def fake_preview(
        _frontier: FrontierWorkStore,
        _active_budget: BudgetVector,
        *,
        memory_pressure: float = 0.0,
        solver_timeout_ms: int = 10000,
        unsat_core_timeout_ms: int = 5000,
    ) -> ShadowDecisionEvaluation:
        _ = memory_pressure
        _ = solver_timeout_ms
        _ = unsat_core_timeout_ms
        return ShadowDecisionEvaluation(
            decision=None,
            outcome=outcome,
            application_plan=plan,
            selected_state_id=0,
            explanation="unit positive preview",
        )

    def fake_apply(_frontier: FrontierWorkStore, _outcome: object) -> int:
        return 0

    monkeypatch.setattr(controller, "preview_shadow_frontier", fake_preview)
    monkeypatch.setattr(controller, "apply_evidence_outcome", fake_apply)

    controller.apply_runtime_evidence(frontier)

    assert len(frontier) == 1
    stats = controller.collect_stats(frontier, enabled=True)
    assert stats.runtime_preview_count == 1
    assert stats.runtime_removed_state_count == 0
    assert stats.runtime_nonremoving_count == 1


def test_runtime_execution_selects_best_detector_state_from_runtime_features() -> None:
    """Resident runtime features prefer detector work with lower resident cost."""
    frontier = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    issue = DeferredStateIssue(issue="detector", site_key=("runtime", "feature"))
    frontier.add_state(
        0,
        VMState(
            pc=1,
            local_vars={f"v{index}": index for index in range(8)},
            deferred_detector_issues=[issue],
        ),
    )
    frontier.add_state(1, VMState(pc=2, deferred_detector_issues=[issue]))
    controller = CegisRuntimeController()

    selected = controller.select_runtime_execution_state_id(frontier)

    assert selected == 1
    stats = controller.collect_stats(frontier, enabled=True)
    assert stats.runtime_execution_select_count == 1
    assert stats.runtime_execution_no_selection_count == 0


def test_runtime_execution_selection_cache_tracks_frontier_mutation() -> None:
    """Repeated runtime selection reuses only unchanged frontier inputs."""
    frontier = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    issue = DeferredStateIssue(issue="detector", site_key=("runtime", "cache"))
    frontier.add_state(
        0,
        VMState(
            pc=1,
            local_vars={f"v{index}": index for index in range(8)},
            deferred_detector_issues=[issue],
        ),
    )
    controller = CegisRuntimeController()

    assert controller.select_runtime_execution_state_id(frontier) == 0

    frontier.add_state(1, VMState(pc=2, deferred_detector_issues=[issue]))

    assert controller.select_runtime_execution_state_id(frontier) == 1

    frontier.discard(1)

    assert controller.select_runtime_execution_state_id(frontier) == 0


def test_runtime_execution_ignores_stale_and_zero_detector_runtime_features() -> None:
    """Runtime-feature selection ignores stale state IDs and zero-obligation entries."""
    frontier = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    frontier.add_state(0, VMState(pc=1))
    frontier.add_state(1, VMState(pc=2))
    frontier.add_state(2, VMState(pc=3))
    frontier.add_state(3, VMState(pc=4))
    runtime_features = cast("dict[int, FrontierRuntimeFeatures]", frontier.runtime_features)
    runtime_features[99] = FrontierRuntimeFeatures(
        capsule_id="path:99",
        detector_obligation_count=10,
        pending_constraint_count=0,
        estimated_resident_units=1,
    )
    runtime_features[0] = FrontierRuntimeFeatures(
        capsule_id="path:0",
        detector_obligation_count=0,
        pending_constraint_count=0,
        estimated_resident_units=1,
    )
    runtime_features[1] = FrontierRuntimeFeatures(
        capsule_id="path:1",
        detector_obligation_count=1,
        pending_constraint_count=0,
        estimated_resident_units=20,
    )
    runtime_features[2] = FrontierRuntimeFeatures(
        capsule_id="path:2",
        detector_obligation_count=1,
        pending_constraint_count=0,
        estimated_resident_units=5,
    )
    runtime_features[3] = FrontierRuntimeFeatures(
        capsule_id="path:3",
        detector_obligation_count=1,
        pending_constraint_count=0,
        estimated_resident_units=30,
    )
    controller = CegisRuntimeController()

    selected = controller.select_runtime_execution_state_id(frontier)

    assert selected == 2


def test_runtime_execution_falls_back_to_capsule_detector_obligations() -> None:
    """Shadow-mode capsules can still drive detector-first execution selection."""
    frontier = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_SHADOW)
    issue = DeferredStateIssue(issue="detector", site_key=("runtime", "capsule"))
    frontier.add_state(0, VMState(pc=1, deferred_detector_issues=[issue]))
    controller = CegisRuntimeController()

    selected = controller.select_runtime_execution_state_id(frontier)

    assert selected == 0
    stats = controller.collect_stats(frontier, enabled=True)
    assert stats.runtime_execution_select_count == 1
    assert stats.runtime_execution_no_selection_count == 0


def test_runtime_execution_ignores_stale_capsules_and_keeps_best_capsule_candidate() -> None:
    """Capsule fallback ignores stale entries and keeps the best detector candidate."""
    frontier = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_SHADOW)
    issue = DeferredStateIssue(issue="detector", site_key=("runtime", "capsule-stale"))
    frontier.add_state(0, VMState(pc=0))
    frontier.add_state(
        1,
        VMState(
            pc=1,
            local_vars={f"v{index}": index for index in range(8)},
            deferred_detector_issues=[issue],
        ),
    )
    frontier.add_state(2, VMState(pc=2, deferred_detector_issues=[issue]))
    frontier.add_state(
        3,
        VMState(
            pc=3,
            local_vars={f"v{index}": index for index in range(12)},
            deferred_detector_issues=[issue],
        ),
    )
    capsules = cast("dict[int, ObligationCapsule]", frontier.capsules)
    capsules[99] = capsules[1]
    controller = CegisRuntimeController()

    selected = controller.select_runtime_execution_state_id(frontier)

    assert selected == 2
