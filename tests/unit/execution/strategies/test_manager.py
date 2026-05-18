from __future__ import annotations

from dataclasses import dataclass
from typing import cast

import pytest
import z3

from pysymex.core.graph.treewidth import ConstraintInteractionGraph
from pysymex.core.state import VMState
from pysymex.execution.strategies.manager import (
    AdaptivePathManager,
    ExplorationStrategy,
    PathManager,
    PrioritizedState,
    create_path_manager,
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

    def test_get_next_state(self) -> None:
        """Test get_next_state behavior."""
        manager = AdaptivePathManager(ConstraintInteractionGraph(), deterministic=True)
        manager.add_state(VMState(pc=3))
        nxt = manager.get_next_state()
        assert nxt is not None and nxt.pc == 3

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

    def test_reheat_arm_recovers_structural_prior_mass(self) -> None:
        """Test reheating pulls a poisoned arm back toward its prior."""
        manager = AdaptivePathManager(ConstraintInteractionGraph(), deterministic=False)
        manager.add_state(VMState(pc=1))
        assert manager.get_next_state() is not None
        for _ in range(25):
            manager.record_reward(-5.0)
        arms_before = cast("dict[str, dict[str, float]]", manager.get_stats()["arms"])
        before = arms_before[manager.ARM_STRUCTURAL]
        manager.reheat_arm(manager.ARM_STRUCTURAL, strength=0.5)
        arms_after = cast("dict[str, dict[str, float]]", manager.get_stats()["arms"])
        after = arms_after[manager.ARM_STRUCTURAL]
        assert after["alpha"] < before["alpha"]
        assert after["beta"] < before["beta"]

    def test_feedback_unsat_core_uses_real_pruning_runtime_telemetry(self) -> None:
        """Thompson reward should reflect actual certified frontier pruning yield."""
        manager = AdaptivePathManager(ConstraintInteractionGraph(), deterministic=True)
        manager.add_state(VMState(pc=1))
        assert manager.get_next_state() is not None
        before = cast("float", manager.get_stats()["total_rewards"])

        manager.feedback_unsat_core([], paths_pruned=3, elapsed_ms=2.0)

        after = cast("float", manager.get_stats()["total_rewards"])
        assert isinstance(before, float)
        assert isinstance(after, float)
        assert after > before

    def test_feedback_mus_alias_is_deprecated(self) -> None:
        manager = AdaptivePathManager(ConstraintInteractionGraph(), deterministic=True)
        manager.add_state(VMState(pc=1))
        assert manager.get_next_state() is not None

        with pytest.warns(DeprecationWarning, match="feedback_mus"):
            manager.feedback_mus([1, 2])

        assert cast("float", manager.get_stats()["total_rewards"]) > 0.0

    def test_prune_states_containing_core_removes_only_certified_core_supersets(self) -> None:
        """Frontier pruning removes queued states only when they contain the certified core."""
        manager = AdaptivePathManager(ConstraintInteractionGraph(), deterministic=True)
        x = z3.Int("frontier_core_x")
        y = z3.Int("frontier_core_y")
        core_left = x > 0
        core_right = x < 0
        unrelated = y > 0

        killed_state = VMState(pc=1)
        killed_state.add_constraint(core_left)
        killed_state.add_constraint(core_right)
        kept_state = VMState(pc=2)
        kept_state.add_constraint(core_left)
        kept_state.add_constraint(unrelated)

        manager.add_state(killed_state)
        manager.add_state(kept_state)

        killed = manager.prune_states_containing_core(
            frozenset({core_left.hash(), core_right.hash()})
        )

        assert killed == 1
        assert manager.size() == 1
        remaining = manager.get_next_state()
        assert remaining is kept_state


def test_create_path_manager() -> None:
    """Test create_path_manager behavior."""
    manager = create_path_manager(ExplorationStrategy.ADAPTIVE, deterministic=True)
    assert isinstance(manager, AdaptivePathManager)
