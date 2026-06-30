from __future__ import annotations

from typing import cast

from pysymex._internal.core.state.deferred import DeferredStateIssue
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.frontier.modes import FrontierRuntimeMode
from pysymex._internal.execution.frontier.runtime.features import FrontierRuntimeFeatures
from pysymex._internal.execution.frontier.store.core import FrontierWorkStore
from pysymex._internal.execution.scheduling.cegis.runtime.controller import CegisRuntimeController


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
    capsules = cast("dict[int, object]", frontier.capsules)
    capsules[99] = capsules[1]
    controller = CegisRuntimeController()

    selected = controller.select_runtime_execution_state_id(frontier)

    assert selected == 2
