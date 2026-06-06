from __future__ import annotations

from dataclasses import dataclass
from typing import cast

import z3

from pysymex.core.graph.cig import ConstraintInteractionGraph
from pysymex.core.state.record import VMState
from pysymex.core.types.havoc import HavocValue
from pysymex.execution.frontier import FrontierRuntimeMode, state_shadow_digest
from pysymex.execution.frontier.store import FrontierRuntimeFeatures
from pysymex.execution.scheduling import create_path_manager
from pysymex.execution.scheduling.telemetry import SchedulerEvent
from pysymex.execution.strategies.manager.pressure import (
    PressureCompactionPolicy,
    runtime_native_priority,
)
from pysymex.execution.strategies.manager.path import AdaptivePathManager
from pysymex.execution.strategies.manager.types import (
    ExplorationStrategy,
    PathManager,
    PrioritizedState,
)


@dataclass
class _DummyState:
    value: int


class _DummyManager(PathManager[_DummyState]):
    def __init__(self) -> None:
        self.items: list[_DummyState] = []

    def add_state(self, state: _DummyState, priority: float = 0.0) -> None:
        _ = priority
        self.items.append(state)

    def get_next_state(self) -> _DummyState | None:
        if self.items:
            return self.items.pop(0)
        return None

    def is_empty(self) -> bool:
        return len(self.items) == 0

    def size(self) -> int:
        return len(self.items)


class _CountingGraph(ConstraintInteractionGraph):
    """Constraint graph that records degree lookups for scheduler overhead tests."""

    def __init__(self) -> None:
        super().__init__()
        self.degree_calls = 0

    def get_degree(self, pc: int) -> int:
        self.degree_calls += 1
        return super().get_degree(pc)


class TestExplorationStrategy:
    """Test suite for pysymex.execution.strategies.manager.ExplorationStrategy."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        names = {item.name for item in ExplorationStrategy}
        assert "ADAPTIVE" in names
        assert len(names) == 1


class TestPathManager:
    """Test suite for pysymex.execution.strategies.manager.PathManager."""

    def test_add_state(self) -> None:
        """Test add_state behavior."""
        manager = _DummyManager()
        manager.add_state(_DummyState(1))
        assert manager.size() == 1

    def test_get_next_state(self) -> None:
        """Test get_next_state behavior."""
        manager = _DummyManager()
        manager.add_state(_DummyState(2))
        state = manager.get_next_state()
        assert state is not None and state.value == 2

    def test_is_empty(self) -> None:
        """Test is_empty behavior."""
        manager = _DummyManager()
        assert manager.is_empty() is True

    def test_size(self) -> None:
        """Test size behavior."""
        manager = _DummyManager()
        manager.add_state(_DummyState(9))
        assert manager.size() == 1


class TestPrioritizedState:
    """Test suite for pysymex.execution.strategies.manager.PrioritizedState."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        a = PrioritizedState[_DummyState](1.0, 1, _DummyState(1))
        b = PrioritizedState[_DummyState](2.0, 2, _DummyState(2))
        assert b < a


class TestAdaptivePathManager:
    """Test suite for pysymex.execution.strategies.manager.AdaptivePathManager."""

    def test_add_state(self) -> None:
        """Test add_state behavior."""
        manager = AdaptivePathManager(ConstraintInteractionGraph(), deterministic=True)
        manager.add_state(VMState())
        assert manager.size() == 1

    def test_record_reward(self) -> None:
        """Test record_reward behavior."""
        manager = AdaptivePathManager(ConstraintInteractionGraph(), deterministic=False)
        manager.add_state(VMState())
        _ = manager.get_next_state()
        before = manager.get_stats()["total_rewards"]
        manager.record_reward(2.0)
        after = manager.get_stats()["total_rewards"]
        assert isinstance(before, float)
        assert isinstance(after, float)
        assert after >= before
        assert manager.get_stats()["path_policy"] == AdaptivePathManager.ARM_POLAR_NATIVE

    def test_get_next_state(self) -> None:
        """Test get_next_state behavior."""
        manager = AdaptivePathManager(ConstraintInteractionGraph(), deterministic=True)
        manager.add_state(VMState(pc=3))
        nxt = manager.get_next_state()
        assert nxt is not None and nxt.pc == 3

    def test_scheduler_events_describe_enqueue_and_selection(self) -> None:
        """POLAR scheduling telemetry records frontier decisions without changing order."""
        events: list[SchedulerEvent] = []
        manager = AdaptivePathManager(ConstraintInteractionGraph(), deterministic=True)
        manager.add_scheduler_event_observer(events.append)

        manager.add_state(
            VMState(
                pc=3,
                path_id=7,
                depth=2,
                pending_constraint_count=1,
            )
        )
        selected = manager.get_next_state()

        assert selected is not None and selected.path_id == 7
        assert len(events) == 2
        enqueue = events[0]
        select = events[1]
        assert enqueue.action == "enqueue"
        assert enqueue.decision_source == "polar_native"
        assert enqueue.path_id == 7
        assert enqueue.frontier_size_before == 0
        assert enqueue.frontier_size_after == 1
        assert enqueue.priority is not None
        assert select.action == "select"
        assert select.decision_source == "polar_native"
        assert select.path_id == 7
        assert select.frontier_size_before == 1
        assert select.frontier_size_after == 0

    def test_native_policy_prefers_high_degree_branch(self) -> None:
        """POLAR-native scheduling targets graph bottlenecks before isolated branches."""
        cig = ConstraintInteractionGraph()
        cig.add_branch(1, {"x"})
        cig.add_branch(2, {"x"})
        cig.add_branch(3, {"y"})
        manager = AdaptivePathManager(cig)

        manager.add_state(VMState(pc=3, depth=0))
        manager.add_state(VMState(pc=1, depth=0))

        nxt = manager.get_next_state()

        assert nxt is not None and nxt.pc == 1

    def test_native_policy_prefers_fewer_pending_constraints_on_ties(self) -> None:
        """POLAR-native scheduling orders tied states by queued constraint burden."""
        manager = AdaptivePathManager(ConstraintInteractionGraph())

        manager.add_state(VMState(pc=1, pending_constraint_count=5))
        manager.add_state(VMState(pc=2, pending_constraint_count=1))

        nxt = manager.get_next_state()

        assert nxt is not None and nxt.pc == 2

    def test_runtime_native_policy_prefers_lower_constraint_cost_on_ties(self) -> None:
        """Default POLAR runtime ordering uses capsule cost without bandit sampling."""
        manager = AdaptivePathManager(ConstraintInteractionGraph(), deterministic=False)

        manager.add_state(VMState(pc=1, pending_constraint_count=5))
        manager.add_state(VMState(pc=1, pending_constraint_count=1))

        admission_stats = manager.get_stats()
        shadow_frontier = cast("dict[str, object]", admission_stats["shadow_frontier"])
        assert shadow_frontier["capsule_count"] == 0
        assert shadow_frontier["checkpoint_count"] == 0

        nxt = manager.get_next_state()

        assert nxt is not None and nxt.pending_constraint_count == 1
        stats = manager.get_stats()
        assert stats["path_policy"] == AdaptivePathManager.ARM_POLAR_NATIVE
        path_arms = cast("dict[str, dict[str, float]]", stats["path_arms"])
        assert path_arms == {}

    def test_runtime_frontier_can_be_compacted_explicitly(self) -> None:
        """Runtime compaction drops resident entries only behind exact checkpoints."""
        manager = AdaptivePathManager(ConstraintInteractionGraph(), deterministic=False)
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

    def test_runtime_pressure_compaction_stays_disabled_below_threshold(self) -> None:
        """Small resident frontiers should not pay checkpoint compaction cost."""
        policy = PressureCompactionPolicy(
            entry_threshold=3,
            resident_unit_threshold=1000,
            check_interval=1,
            batch_size=1,
        )
        manager = AdaptivePathManager(
            ConstraintInteractionGraph(),
            deterministic=False,
            pressure_policy=policy,
        )

        manager.add_state(VMState(pc=1))
        manager.add_state(VMState(pc=2))

        stats = manager.get_stats()
        shadow_frontier = cast("dict[str, object]", stats["shadow_frontier"])
        assert shadow_frontier["compacted_entry_count"] == 0
        assert shadow_frontier["pressure_compaction_count"] == 0
        assert shadow_frontier["pressure_compaction_trigger_count"] == 0

    def test_runtime_pressure_compaction_compacts_bounded_cold_batch(self) -> None:
        """High-pressure resident frontiers compact only the configured cold batch."""
        policy = PressureCompactionPolicy(
            entry_threshold=3,
            resident_unit_threshold=1000,
            check_interval=1,
            batch_size=1,
        )
        manager = AdaptivePathManager(
            ConstraintInteractionGraph(),
            deterministic=False,
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

    def test_runtime_pressure_policy_can_disable_compaction_with_zero_batch(self) -> None:
        """A zero-size pressure batch is an explicit no-op policy."""
        policy = PressureCompactionPolicy(
            entry_threshold=1,
            resident_unit_threshold=1,
            check_interval=1,
            batch_size=0,
        )

        assert policy.should_check(live_entry_count=10, resident_units=10) is False

    def test_runtime_native_priority_uses_runtime_features_when_available(self) -> None:
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

    def test_adaptive_add_state_looks_up_branch_degree_once_per_state(self) -> None:
        """Adaptive enqueue reuses graph-degree scoring across heap priorities."""
        cig = _CountingGraph()
        manager = AdaptivePathManager(cig, deterministic=False)

        manager.add_state(VMState(pc=1))
        manager.add_state(VMState(pc=2))

        assert cig.degree_calls == 2

    def test_is_empty(self) -> None:
        """Test is_empty behavior."""
        manager = AdaptivePathManager(ConstraintInteractionGraph(), deterministic=True)
        assert manager.is_empty() is True

    def test_size(self) -> None:
        """Test size behavior."""
        manager = AdaptivePathManager(ConstraintInteractionGraph(), deterministic=True)
        manager.add_state(VMState())
        assert manager.size() == 1

    def test_get_stats(self) -> None:
        """Test get_stats behavior."""
        manager = AdaptivePathManager(ConstraintInteractionGraph(), deterministic=True)
        stats = manager.get_stats()
        assert "arms" in stats
        assert "covered_pcs" in stats

    def test_shadow_frontier_stats_track_live_queued_states(self) -> None:
        """POLAR/CEGIS shadow telemetry follows the live frontier without selecting work."""
        manager = AdaptivePathManager(
            ConstraintInteractionGraph(),
            deterministic=True,
            frontier_runtime_mode=FrontierRuntimeMode.POLAR_CEGIS_SHADOW,
        )
        x = z3.Int("shadow_frontier_x")
        havoc_value, _ = HavocValue.havoc("shadow_frontier_havoc")

        manager.add_state(VMState(pc=1, path_constraints=[x > 0], pending_constraint_count=1))
        manager.add_state(VMState(pc=2, stack=[havoc_value]))

        stats = manager.get_stats()
        shadow_frontier = cast("dict[str, object]", stats["shadow_frontier"])
        shadow_cegis = cast("dict[str, object]", stats["shadow_cegis"])
        assert stats["frontier_mode"] == FrontierRuntimeMode.POLAR_CEGIS_SHADOW.value
        assert shadow_frontier["enabled"] is True
        assert shadow_cegis["enabled"] is True
        assert shadow_frontier["capsule_count"] == 2
        assert shadow_frontier["checkpoint_count"] == 0
        assert shadow_frontier["capsule_digest_mismatch_count"] == 0
        assert shadow_frontier["reconstruction_mismatch_count"] == 0
        assert shadow_frontier["spill_denied_count"] == 0
        assert shadow_frontier["constraint_atom_count"] == 1
        assert shadow_frontier["pending_constraint_count"] == 1
        assert shadow_frontier["unsupported_live_count"] == 0
        assert shadow_frontier["havoc_live_count"] == 1
        assert shadow_cegis["bid_count"] == 3

        selected = manager.get_next_state()
        stats_after_pop = manager.get_stats()
        shadow_after_pop = cast("dict[str, object]", stats_after_pop["shadow_frontier"])
        cegis_after_pop = cast("dict[str, object]", stats_after_pop["shadow_cegis"])

        assert selected is not None and selected.pc == 2
        assert shadow_after_pop["capsule_count"] == 1
        assert shadow_after_pop["checkpoint_count"] == 0
        assert shadow_after_pop["capsule_digest_mismatch_count"] == 0
        assert shadow_after_pop["reconstruction_mismatch_count"] == 0
        assert shadow_after_pop["spill_denied_count"] == 0
        assert shadow_after_pop["constraint_atom_count"] == 1
        assert shadow_after_pop["pending_constraint_count"] == 1
        assert shadow_after_pop["havoc_live_count"] == 0
        assert cegis_after_pop["bid_count"] == 2


def test_create_path_manager() -> None:
    """Test create_path_manager behavior."""
    manager = create_path_manager(ExplorationStrategy.ADAPTIVE, deterministic=True)
    assert isinstance(manager, AdaptivePathManager)
    assert manager.get_stats()["frontier_mode"] == FrontierRuntimeMode.POLAR_CEGIS_RUNTIME.value
    assert manager.get_stats()["path_policy"] == AdaptivePathManager.ARM_POLAR_NATIVE
