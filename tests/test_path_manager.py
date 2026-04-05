"""Tests for path manager (analysis/path_manager.py).

Phase 4 -- covers CHTD-native, Priority, CoverageGuided, Directed,
and Adaptive path managers.
"""
from __future__ import annotations
import pytest
from pysymex.analysis.path_manager import (
    ExplorationStrategy,
    CHTDNativePathManager,
    PriorityPathManager,
    CoverageGuidedPathManager,
    DirectedPathManager,
    AdaptivePathManager,
    create_path_manager,
)


class TestExplorationStrategy:
    def test_enum_values(self):
        assert ExplorationStrategy.CHTD_NATIVE is not None
        assert ExplorationStrategy.ADAPTIVE is not None

    def test_enum_members_count(self):
        assert len(ExplorationStrategy) >= 2


class TestCHTDNativePathManager:
    def test_add_and_get(self):
        pm = CHTDNativePathManager()
        from tests.helpers import make_state
        st1 = make_state(pc=1)
        st2 = make_state(pc=2)
        pm.add_state(st1)
        pm.add_state(st2)
        assert pm.get_next_state() is not None

    def test_empty(self):
        pm = CHTDNativePathManager()
        assert pm.is_empty()

    def test_not_empty_after_add(self):
        pm = CHTDNativePathManager()
        from tests.helpers import make_state
        pm.add_state(make_state())
        assert not pm.is_empty()

    def test_length(self):
        pm = CHTDNativePathManager()
        from tests.helpers import make_state
        pm.add_state(make_state(pc=1))
        pm.add_state(make_state(pc=2))
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
    def test_chtd_native(self):
        pm = create_path_manager(ExplorationStrategy.CHTD_NATIVE)
        assert isinstance(pm, AdaptivePathManager)
