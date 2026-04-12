from __future__ import annotations

from dataclasses import dataclass

from pysymex.core.state import VMState
from pysymex.execution.strategies.manager import (
    AdaptivePathManager,
    CHTDNativePathManager,
    CoverageGuidedPathManager,
    DirectedPathManager,
    ExplorationStrategy,
    PathManager,
    PrioritizedState,
    PriorityPathManager,
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
        a = PrioritizedState[_DummyState](1.0, _DummyState(1))
        b = PrioritizedState[_DummyState](2.0, _DummyState(2))
        assert a < b


class TestPriorityPathManager:
    """Test suite for pysymex.execution.strategies.manager.PriorityPathManager."""
    def test_add_state(self) -> None:
        """Test add_state behavior."""
        manager = PriorityPathManager[_DummyState]()
        manager.add_state(_DummyState(1), priority=1.0)
        assert manager.size() == 1

    def test_get_next_state(self) -> None:
        """Test get_next_state behavior."""
        manager = PriorityPathManager[_DummyState]()
        manager.add_state(_DummyState(10), priority=5.0)
        manager.add_state(_DummyState(20), priority=1.0)
        nxt = manager.get_next_state()
        assert nxt is not None and nxt.value == 20

    def test_is_empty(self) -> None:
        """Test is_empty behavior."""
        manager = PriorityPathManager[_DummyState]()
        assert manager.is_empty() is True

    def test_size(self) -> None:
        """Test size behavior."""
        manager = PriorityPathManager[_DummyState]()
        manager.add_state(_DummyState(1), priority=0.0)
        assert manager.size() == 1


class TestCoverageGuidedPathManager:
    """Test suite for pysymex.execution.strategies.manager.CoverageGuidedPathManager."""
    def test_add_state(self) -> None:
        """Test add_state behavior."""
        manager = CoverageGuidedPathManager()
        manager.add_state(VMState(visited_pcs={1, 2}))
        assert manager.size() == 1

    def test_get_next_state(self) -> None:
        """Test get_next_state behavior."""
        manager = CoverageGuidedPathManager()
        manager.add_state(VMState(visited_pcs={3}))
        nxt = manager.get_next_state()
        assert nxt is not None
        assert 3 in manager.get_coverage()[1]

    def test_is_empty(self) -> None:
        """Test is_empty behavior."""
        manager = CoverageGuidedPathManager()
        assert manager.is_empty() is True

    def test_size(self) -> None:
        """Test size behavior."""
        manager = CoverageGuidedPathManager()
        manager.add_state(VMState())
        assert manager.size() == 1

    def test_get_coverage(self) -> None:
        """Test get_coverage behavior."""
        manager = CoverageGuidedPathManager()
        manager.add_state(VMState(visited_pcs={5}))
        _ = manager.get_next_state()
        count, pcs = manager.get_coverage()
        assert count == 1
        assert 5 in pcs


class TestCHTDNativePathManager:
    """Test suite for pysymex.execution.strategies.manager.CHTDNativePathManager."""
    def test_add_state(self) -> None:
        """Test add_state behavior."""
        manager = CHTDNativePathManager()
        manager.add_state(VMState())
        assert manager.size() == 1

    def test_get_next_state(self) -> None:
        """Test get_next_state behavior."""
        manager = CHTDNativePathManager()
        manager.add_state(VMState(visited_pcs={9}))
        nxt = manager.get_next_state()
        assert nxt is not None

    def test_is_empty(self) -> None:
        """Test is_empty behavior."""
        manager = CHTDNativePathManager()
        assert manager.is_empty() is True

    def test_size(self) -> None:
        """Test size behavior."""
        manager = CHTDNativePathManager()
        manager.add_state(VMState())
        assert manager.size() == 1


class TestDirectedPathManager:
    """Test suite for pysymex.execution.strategies.manager.DirectedPathManager."""
    def test_add_state(self) -> None:
        """Test add_state behavior."""
        manager = DirectedPathManager({100})
        manager.add_state(VMState(pc=10))
        assert manager.size() == 1

    def test_get_next_state(self) -> None:
        """Test get_next_state behavior."""
        manager = DirectedPathManager({5})
        manager.add_state(VMState(pc=100))
        nxt = manager.get_next_state()
        assert nxt is not None

    def test_is_empty(self) -> None:
        """Test is_empty behavior."""
        manager = DirectedPathManager({1})
        assert manager.is_empty() is True

    def test_size(self) -> None:
        """Test size behavior."""
        manager = DirectedPathManager({1})
        manager.add_state(VMState(pc=1))
        assert manager.size() == 1


class TestAdaptivePathManager:
    """Test suite for pysymex.execution.strategies.manager.AdaptivePathManager."""
    def test_add_state(self) -> None:
        """Test add_state behavior."""
        manager = AdaptivePathManager(deterministic=True)
        manager.add_state(VMState())
        assert manager.size() == 1

    def test_record_reward(self) -> None:
        """Test record_reward behavior."""
        manager = AdaptivePathManager(deterministic=False)
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
        manager = AdaptivePathManager(deterministic=True)
        manager.add_state(VMState(pc=3))
        nxt = manager.get_next_state()
        assert nxt is not None and nxt.pc == 3

    def test_is_empty(self) -> None:
        """Test is_empty behavior."""
        manager = AdaptivePathManager(deterministic=True)
        assert manager.is_empty() is True

    def test_size(self) -> None:
        """Test size behavior."""
        manager = AdaptivePathManager(deterministic=True)
        manager.add_state(VMState())
        assert manager.size() == 1

    def test_get_stats(self) -> None:
        """Test get_stats behavior."""
        manager = AdaptivePathManager(deterministic=True)
        stats = manager.get_stats()
        assert "arms" in stats
        assert "selections" in stats

    def test_reheat_arm_recovers_structural_prior_mass(self) -> None:
        """Test reheating pulls a poisoned arm back toward its prior."""
        manager = AdaptivePathManager(deterministic=False, gamma=0.95)
        manager._last_arm = manager.ARM_STRUCTURAL
        for _ in range(25):
            manager.record_reward(-5.0)
        before = manager.get_stats()["arms"]["structural"]
        manager.reheat_arm(manager.ARM_STRUCTURAL, strength=0.5)
        after = manager.get_stats()["arms"]["structural"]
        assert after["alpha"] > before["alpha"]
        assert after["beta"] < before["beta"]


def test_create_path_manager() -> None:
    """Test create_path_manager behavior."""
    manager = create_path_manager(ExplorationStrategy.RANDOM, deterministic=True)
    assert isinstance(manager, AdaptivePathManager)
