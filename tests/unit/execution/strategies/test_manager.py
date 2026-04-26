from __future__ import annotations

from dataclasses import dataclass

from pysymex.core.graph.cig import ConstraintInteractionGraph
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
        assert "CHTD_NATIVE" in names


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
        manager.tts.last_arm = manager.ARM_STRUCTURAL
        for _ in range(25):
            manager.record_reward(-5.0)
        before = manager.get_stats()["arms"]["topological"]
        manager.reheat_arm(manager.ARM_STRUCTURAL, strength=0.5)
        after = manager.get_stats()["arms"]["topological"]
        assert after["alpha"] < before["alpha"]
        assert after["beta"] < before["beta"]


def test_create_path_manager() -> None:
    """Test create_path_manager behavior."""
    manager = create_path_manager(ExplorationStrategy.RANDOM, deterministic=True)
    assert isinstance(manager, AdaptivePathManager)
