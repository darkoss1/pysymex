from __future__ import annotations

from typing import cast

import z3
from pytest import MonkeyPatch

from pysymex._internal.core.graph.cig import ConstraintInteractionGraph
from pysymex._internal.core.solver.engine.incremental import IncrementalSolver
from pysymex._internal.core.solver.engine.results import SolverResult
from pysymex._internal.core.state.deferred import DeferredStateIssue
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.frontier.entries import realize_frontier_queue_entry
from pysymex._internal.execution.frontier.modes import FrontierRuntimeMode
from pysymex._internal.execution.frontier.obligations.digests import state_shadow_digest
from pysymex._internal.execution.strategies.manager.path import AdaptivePathManager


def _shadow_cegis_stats(manager: AdaptivePathManager) -> dict[str, object]:
    stats = manager.get_stats()
    return cast("dict[str, object]", stats["shadow_cegis"])


def _unknown_solver_check(
    self: object,
    constraints: object,
    known_sat_prefix_len: object = None,
) -> SolverResult:
    _ = self
    _ = constraints
    _ = known_sat_prefix_len
    return SolverResult.unknown()


def test_runtime_cegis_mode_keeps_duplicate_work_during_hot_path_selection() -> None:
    """Runtime mode does not automatically prune duplicates during hot path selection."""
    manager = AdaptivePathManager(
        ConstraintInteractionGraph(),
        frontier_runtime_mode=FrontierRuntimeMode.POLAR_CEGIS_RUNTIME,
    )
    selected_state = VMState(pc=7)
    dominated_state = VMState(pc=7)
    manager.add_state(selected_state)
    manager.add_state(dominated_state)

    selected = manager.get_next_state()

    assert selected is not None
    assert selected is selected_state
    assert state_shadow_digest(selected) == state_shadow_digest(selected_state)
    queued_digests = frozenset(
        state_shadow_digest(realize_frontier_queue_entry(entry))
        for entry in manager.states.values()
    )
    assert state_shadow_digest(dominated_state) in queued_digests
    shadow_cegis = _shadow_cegis_stats(manager)
    assert shadow_cegis["evidence_apply_count"] == 0
    assert shadow_cegis["evidence_apply_removed_state_count"] == 0
    assert shadow_cegis["runtime_execution_select_count"] == 0
    assert shadow_cegis["runtime_execution_no_selection_count"] == 1


def test_runtime_cegis_mode_keeps_solver_unknown_state_explorable(
    monkeypatch: MonkeyPatch,
) -> None:
    """Runtime proof application never treats solver UNKNOWN as removable work."""
    monkeypatch.setattr(
        IncrementalSolver,
        "check_sat_result",
        _unknown_solver_check,
    )
    manager = AdaptivePathManager(
        ConstraintInteractionGraph(),
        frontier_runtime_mode=FrontierRuntimeMode.POLAR_CEGIS_RUNTIME,
    )
    x = z3.Int("manager_runtime_cegis_unknown")
    state = VMState(path_constraints=[x > 0], pending_constraint_count=1)
    manager.add_state(state)

    selected = manager.get_next_state()

    assert selected is not None
    assert selected is state
    assert state_shadow_digest(selected) == state_shadow_digest(state)
    shadow_cegis = _shadow_cegis_stats(manager)
    assert shadow_cegis["evidence_apply_count"] == 0


def test_runtime_cegis_mode_keeps_unsat_core_siblings_during_hot_path_selection() -> None:
    """Runtime get-next-state does not automatically consume unsat-core certificates."""
    manager = AdaptivePathManager(
        ConstraintInteractionGraph(),
        frontier_runtime_mode=FrontierRuntimeMode.POLAR_CEGIS_RUNTIME,
    )
    x = z3.Int("manager_runtime_cegis_unsat_reuse")
    positive = x > 0
    nonpositive = x <= 0
    manager.add_state(
        VMState(
            pc=11,
            path_constraints=[positive, nonpositive],
            pending_constraint_count=2,
        )
    )
    manager.add_state(
        VMState(
            pc=12,
            path_constraints=[positive, nonpositive],
            pending_constraint_count=2,
        )
    )

    selected = manager.get_next_state()

    assert selected is not None
    assert manager.size() == 1
    shadow_cegis = _shadow_cegis_stats(manager)
    assert shadow_cegis["evidence_apply_count"] == 0
    assert shadow_cegis["evidence_apply_removed_state_count"] == 0
    assert shadow_cegis["runtime_execution_select_count"] == 0


def test_runtime_cegis_mode_selects_execute_bid_before_native_order() -> None:
    """Runtime execution selection is driven by CEGIS execute bids."""
    cig = ConstraintInteractionGraph()
    cig.add_branch(10, {"x", "y", "z"})
    cig.add_branch(20, {"x"})
    manager = AdaptivePathManager(
        cig,
        frontier_runtime_mode=FrontierRuntimeMode.POLAR_CEGIS_RUNTIME,
    )
    structural_state = VMState(pc=10)
    detector_state = VMState(
        pc=20,
        deferred_detector_issues=[
            DeferredStateIssue(issue="detector", site_key=("runtime", "detector")),
        ],
    )
    manager.add_state(structural_state)
    manager.add_state(detector_state)

    selected = manager.get_next_state()

    assert selected is not None
    assert selected.pc == 20
    assert state_shadow_digest(selected) == state_shadow_digest(detector_state)
    shadow_cegis = _shadow_cegis_stats(manager)
    assert shadow_cegis["runtime_execution_select_count"] == 1
    assert shadow_cegis["runtime_execution_no_selection_count"] == 0
