from __future__ import annotations

from pysymex._internal.core.solver.engine.results import SolverResult
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.frontier.modes import FrontierRuntimeMode
from pysymex._internal.execution.frontier.store.core import FrontierWorkStore
from pysymex._internal.execution.scheduling.cegis.application import EvidenceApplicationPlan
from pysymex._internal.execution.scheduling.cegis.bids.types import (
    EvidenceAction,
    EvidenceActionKind,
    EvidenceOwner,
)
from pysymex._internal.execution.scheduling.cegis.budgets import BudgetVector
from pysymex._internal.execution.scheduling.cegis.outcomes.solver import solver_unsat_core_outcome
from pysymex._internal.execution.scheduling.cegis.runtime.accounting import CegisRuntimeAccounting
from pysymex._internal.execution.scheduling.cegis.runtime.controller import CegisRuntimeController
from pysymex._internal.execution.scheduling.cegis.runtime.controller import (
    CegisRuntimeController as CegisRuntimeControllerOwner,
)
from pysymex._internal.execution.scheduling.cegis.runtime.stats import CegisRuntimeStats


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


def test_cegis_runtime_accounting_records_stats_snapshot() -> None:
    """Runtime accounting owns deterministic CEGIS telemetry counters."""
    outcome = solver_unsat_core_outcome(
        _solver_action("path:0"),
        SolverResult.unsat(),
        covered_capsule_ids=("path:0",),
        core_indices=(0,),
    )
    removable_plan = EvidenceApplicationPlan(
        outcome=outcome,
        removable_state_ids=(0,),
        removable_capsule_ids=("path:0",),
        invalid_removal_attempt=False,
        explanation="unit removable plan",
    )
    invalid_plan = EvidenceApplicationPlan(
        outcome=outcome,
        removable_state_ids=(1,),
        removable_capsule_ids=("path:1",),
        invalid_removal_attempt=True,
        explanation="unit invalid plan",
    )
    accounting = CegisRuntimeAccounting()

    accounting.record_evidence_preview(removable_plan)
    accounting.record_evidence_preview(invalid_plan)
    accounting.record_evidence_apply(removable_plan, removed_state_count=1)
    accounting.record_evidence_apply(invalid_plan, removed_state_count=0)
    accounting.record_runtime_execution_selection(True)
    accounting.record_runtime_execution_selection(False)

    stats = accounting.collect_stats(enabled=True, bid_count=3)

    assert stats.enabled is True
    assert stats.bid_count == 3
    assert stats.evidence_preview_count == 2
    assert stats.evidence_preview_removable_state_count == 1
    assert stats.evidence_preview_invalid_count == 1
    assert stats.evidence_apply_count == 2
    assert stats.evidence_apply_removed_state_count == 1
    assert stats.evidence_apply_invalid_count == 1
    assert stats.runtime_execution_select_count == 1
    assert stats.runtime_execution_no_selection_count == 1


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


def test_runtime_public_exports_point_to_direct_owners() -> None:
    """The package import surface stays wired to the split runtime owners."""
    from pysymex._internal.execution.scheduling.cegis.runtime.accounting import (
        CegisRuntimeStats as ExportedStats,
    )

    assert CegisRuntimeController is CegisRuntimeControllerOwner
    assert ExportedStats is CegisRuntimeStats
