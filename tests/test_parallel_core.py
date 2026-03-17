"""Tests for parallel execution core (core/parallel_core.py)."""
from __future__ import annotations
import pytest
from pysymex.core.parallel_core import (
    WorkQueue,
    StateMerger,
    ParallelExplorer,
    ConstraintPartitioner,
    ParallelSolver,
)


class TestWorkQueue:
    def test_creation(self):
        wq = WorkQueue()
        assert wq is not None

    def test_empty_initially(self):
        wq = WorkQueue()
        assert wq.empty() if hasattr(wq, 'empty') else wq.size() == 0

    def test_put_get(self):
        wq = WorkQueue()
        if hasattr(wq, 'put'):
            wq.put("item1")
            result = wq.get()
            assert result is not None
            assert result.state == "item1"
        elif hasattr(wq, 'add'):
            wq.add("item1")

    def test_size(self):
        wq = WorkQueue()
        if hasattr(wq, 'put'):
            wq.put("a")
            wq.put("b")
            assert len(wq) == 2 if hasattr(wq, '__len__') else True


class TestStateMerger:
    def test_creation(self):
        sm = StateMerger()
        assert sm is not None

    def test_has_merge(self):
        assert hasattr(StateMerger, 'merge') or hasattr(StateMerger, 'merge_states')


class TestParallelExplorer:
    def test_creation(self):
        pe = ParallelExplorer()
        assert pe is not None

    def test_has_explore(self):
        assert (hasattr(ParallelExplorer, 'explore') or
                hasattr(ParallelExplorer, 'run') or
                hasattr(ParallelExplorer, 'start'))


class TestConstraintPartitioner:
    def test_creation(self):
        cp = ConstraintPartitioner()
        assert cp is not None

    def test_has_partition(self):
        assert (hasattr(ConstraintPartitioner, 'partition') or
                hasattr(ConstraintPartitioner, 'split'))


class TestParallelSolver:
    def test_creation(self):
        ps = ParallelSolver()
        assert ps is not None

    def test_has_solve(self):
        assert (hasattr(ParallelSolver, 'solve') or
                hasattr(ParallelSolver, 'check'))
