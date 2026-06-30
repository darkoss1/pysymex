from __future__ import annotations

from typing import cast

from pysymex._internal.core.graph.cig import ConstraintInteractionGraph
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.frontier.obligations.digests import state_shadow_digest
from pysymex._internal.execution.frontier.runtime.features import FrontierRuntimeFeatures
from pysymex._internal.execution.strategies.manager.path import AdaptivePathManager
from pysymex._internal.execution.strategies.manager.pressure import (
    PressureCompactionPolicy,
    runtime_native_priority,
)


def test_runtime_frontier_can_be_compacted_explicitly() -> None:
    """Runtime compaction drops resident entries only behind exact checkpoints."""
    manager = AdaptivePathManager(ConstraintInteractionGraph())
    state = VMState(pc=4, local_vars={"x": 1}, path_id=3, depth=2)
    manager.add_state(state)

    assert manager.compact_runtime_frontier() == 1

    stats = manager.get_stats()
    shadow_frontier = cast("dict[str, object]", stats["shadow_frontier"])
    assert shadow_frontier["checkpoint_count"] == 1
    assert shadow_frontier["compacted_entry_count"] == 1

    selected = manager.get_next_state()

    assert selected is not None
    assert selected is not state
    assert state_shadow_digest(selected) == state_shadow_digest(state)


def test_runtime_pressure_compaction_stays_disabled_below_threshold() -> None:
    """Small resident frontiers should not pay checkpoint compaction cost."""
    policy = PressureCompactionPolicy(
        entry_threshold=3,
        resident_unit_threshold=1000,
        check_interval=1,
        batch_size=1,
    )
    manager = AdaptivePathManager(
        ConstraintInteractionGraph(),
        pressure_policy=policy,
    )

    manager.add_state(VMState(pc=1))
    manager.add_state(VMState(pc=2))

    stats = manager.get_stats()
    shadow_frontier = cast("dict[str, object]", stats["shadow_frontier"])
    assert shadow_frontier["compacted_entry_count"] == 0
    assert shadow_frontier["pressure_compaction_count"] == 0
    assert shadow_frontier["pressure_compaction_trigger_count"] == 0


def test_runtime_pressure_compaction_compacts_bounded_cold_batch() -> None:
    """High-pressure resident frontiers compact only the configured cold batch."""
    policy = PressureCompactionPolicy(
        entry_threshold=3,
        resident_unit_threshold=1000,
        check_interval=1,
        batch_size=1,
    )
    manager = AdaptivePathManager(
        ConstraintInteractionGraph(),
        pressure_policy=policy,
    )

    manager.add_state(VMState(pc=1, local_vars={"x": 1}))
    manager.add_state(VMState(pc=2, local_vars={"y": 2}))
    manager.add_state(VMState(pc=3, local_vars={"z": 3}))

    stats = manager.get_stats()
    shadow_frontier = cast("dict[str, object]", stats["shadow_frontier"])
    assert shadow_frontier["compacted_entry_count"] == 1
    assert shadow_frontier["pressure_compaction_count"] == 1
    assert shadow_frontier["pressure_compaction_trigger_count"] == 1
    assert manager.size() == 3


def test_runtime_pressure_policy_can_disable_compaction_with_zero_batch() -> None:
    """A zero-size pressure batch is an explicit no-op policy."""
    policy = PressureCompactionPolicy(
        entry_threshold=1,
        resident_unit_threshold=1,
        check_interval=1,
        batch_size=0,
    )

    assert policy.should_check(live_entry_count=10, resident_units=10) is False


def test_runtime_native_priority_uses_runtime_features_when_available() -> None:
    """Runtime features can lower cold, unsupported-heavy states without capsules."""
    state = VMState(pc=1, pending_constraint_count=1, depth=2)
    resident_priority = runtime_native_priority(
        state=state,
        branch_degree=1,
        features=None,
        estimated_resident_units=1,
    )
    featured_priority = runtime_native_priority(
        state=state,
        branch_degree=1,
        features=FrontierRuntimeFeatures(
            capsule_id="path:unit",
            detector_obligation_count=0,
            pending_constraint_count=1,
            estimated_resident_units=20,
            unsupported_live_count=1,
            havoc_live_count=1,
        ),
        estimated_resident_units=1,
    )

    assert featured_priority < resident_priority
