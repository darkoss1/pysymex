"""Tests for path manager (analysis/path_manager.py).

Phase 4 -- covers DFS, BFS, Priority, CoverageGuided, Directed,
and Adaptive path managers.
"""
from __future__ import annotations
import pytest
from pysymex.analysis.path_manager import (
    ExplorationStrategy,
    DFSPathManager,
    BFSPathManager,
    PriorityPathManager,
    CoverageGuidedPathManager,
    DirectedPathManager,
    AdaptivePathManager,
    create_path_manager,
)


class TestExplorationStrategy:
    def test_enum_values(self):
        assert ExplorationStrategy.DFS is not None
        assert ExplorationStrategy.BFS is not None

    def test_enum_members_count(self):
        assert len(ExplorationStrategy) >= 2


class TestDFSPathManager:
    def test_add_and_get(self):
        pm = DFSPathManager()
        pm.add_state("state1")
        pm.add_state("state2")
        assert pm.get_next_state() == "state2"  # LIFO

    def test_empty(self):
        pm = DFSPathManager()
        assert pm.is_empty()

    def test_not_empty_after_add(self):
        pm = DFSPathManager()
        pm.add_state("s")
        assert not pm.is_empty()

    def test_length(self):
        pm = DFSPathManager()
        pm.add_state("a")
        pm.add_state("b")
        assert pm.size() == 2


class TestBFSPathManager:
    def test_add_and_get(self):
        pm = BFSPathManager()
        pm.add_state("state1")
        pm.add_state("state2")
        assert pm.get_next_state() == "state1"  # FIFO

    def test_empty(self):
        pm = BFSPathManager()
        assert pm.is_empty()

    def test_length(self):
        pm = BFSPathManager()
        pm.add_state("a")
        pm.add_state("b")
        assert pm.size() == 2


class TestPriorityPathManager:
    def test_add_and_get(self):
        pm = PriorityPathManager()
        pm.add_state("low", priority=10)
        pm.add_state("high", priority=1)
        result = pm.get_next_state()
        assert result is not None

    def test_empty(self):
        pm = PriorityPathManager()
        assert pm.is_empty()


class TestCoverageGuidedPathManager:
    def test_creation(self):
        pm = CoverageGuidedPathManager()
        assert pm is not None
        assert pm.is_empty()

    def test_add(self):
        pm = CoverageGuidedPathManager()
        from tests.helpers import make_state
        st = make_state()
        pm.add_state(st)
        assert not pm.is_empty()


class TestDirectedPathManager:
    def test_creation(self):
        pm = DirectedPathManager(targets=set())
        assert pm is not None
        assert pm.is_empty()


class TestAdaptivePathManager:
    def test_creation(self):
        pm = AdaptivePathManager()
        assert pm is not None
        assert pm.is_empty()

    def test_add_and_get(self):
        pm = AdaptivePathManager()
        from tests.helpers import make_state
        st = make_state()
        pm.add_state(st)
        assert not pm.is_empty()
        result = pm.get_next_state()
        assert result is not None

    def test_reward_update(self):
        pm = AdaptivePathManager()
        from tests.helpers import make_state
        st = make_state()
        pm.add_state(st)
        pm.get_next_state()
        # reward_update should not raise
        if hasattr(pm, 'record_reward'):
            pm.record_reward(1.0)
        elif hasattr(pm, 'update_reward'):
            pm.update_reward(1.0)


class TestCreatePathManager:
    def test_dfs(self):
        pm = create_path_manager(ExplorationStrategy.DFS)
        assert isinstance(pm, DFSPathManager)

    def test_bfs(self):
        pm = create_path_manager(ExplorationStrategy.BFS)
        assert isinstance(pm, BFSPathManager)
