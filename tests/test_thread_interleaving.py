"""Tests for DPOR thread interleaving explorer."""

import pytest


from pysymex.analysis.concurrency import (
    HappensBeforeGraph,
    MemoryOperation,
    OperationKind,
)

from pysymex.analysis.interleaving import (
    DPORExplorer,
    InterleavingState,
    Transition,
    explore_interleavings,
)


def _make_op(op_id, thread_id, kind, address, value=None):
    """Helper to create a MemoryOperation."""

    return MemoryOperation(
        thread_id=thread_id,
        operation=kind,
        address=address,
        value=value,
        timestamp=op_id,
    )


class TestTransition:
    """Transition dataclass."""

    def test_create(self):
        op = _make_op(0, "t0", OperationKind.READ, "x")

        t = Transition(thread_id="t0", operation=op, op_id=0)

        assert t.thread_id == "t0"

        assert t.op_id == 0

        assert t.enabled is True

    def test_frozen(self):
        op = _make_op(0, "t0", OperationKind.READ, "x")

        t = Transition(thread_id="t0", operation=op, op_id=0)

        assert hash(t) is not None


class TestInterleavingState:
    """Interleaving state management."""

    def test_create_empty(self):
        state = InterleavingState()

        assert state.schedule == []

        assert state.thread_states == {}

    def test_clone(self):
        state = InterleavingState(
            thread_states={"t0": 0, "t1": 1},
            backtrack_set={"t0"},
        )

        cloned = state.clone()

        assert cloned.thread_states == {"t0": 0, "t1": 1}

        cloned.thread_states["t0"] = 99

        assert state.thread_states["t0"] == 0


class TestDPORExplorerBasic:
    """Basic DPOR exploration."""

    def _build_simple_scenario(self):
        """Two threads, one shared variable."""

        hb = HappensBeforeGraph()

        ops = [
            _make_op(0, "t0", OperationKind.WRITE, "x", "1"),
            _make_op(1, "t1", OperationKind.READ, "x"),
        ]

        for op in ops:
            hb.add_operation(op)

        thread_ops = {"t0": [0], "t1": [1]}

        return hb, thread_ops

    def test_simple_two_thread(self):
        hb, thread_ops = self._build_simple_scenario()

        explorer = DPORExplorer(hb, thread_ops)

        schedules = explorer.explore()

        assert len(schedules) >= 1

    def test_empty_threads(self):
        hb = HappensBeforeGraph()

        explorer = DPORExplorer(hb, {})

        schedules = explorer.explore()

        assert schedules == []

    def test_single_thread(self):
        hb = HappensBeforeGraph()

        op = _make_op(0, "t0", OperationKind.WRITE, "x", "1")

        hb.add_operation(op)

        explorer = DPORExplorer(hb, {"t0": [0]})

        schedules = explorer.explore()

        assert len(schedules) == 1

        assert len(schedules[0]) == 1


class TestDPORDependency:
    """Dependent vs independent transitions."""

    def test_independent_no_conflict(self):
        """Operations on different addresses are independent."""

        hb = HappensBeforeGraph()

        ops = [
            _make_op(0, "t0", OperationKind.WRITE, "x", "1"),
            _make_op(1, "t1", OperationKind.WRITE, "y", "2"),
        ]

        for op in ops:
            hb.add_operation(op)

        explorer = DPORExplorer(hb, {"t0": [0], "t1": [1]})

        schedules = explorer.explore()

        assert len(schedules) >= 1

    def test_dependent_same_address(self):
        """Write-write on same address from different threads are dependent."""

        hb = HappensBeforeGraph()

        ops = [
            _make_op(0, "t0", OperationKind.WRITE, "x", "1"),
            _make_op(1, "t1", OperationKind.WRITE, "x", "2"),
        ]

        for op in ops:
            hb.add_operation(op)

        explorer = DPORExplorer(hb, {"t0": [0], "t1": [1]})

        schedules = explorer.explore()

        assert len(schedules) >= 1

    def test_read_read_independent(self):
        """Two reads on same address are independent (no conflict)."""

        hb = HappensBeforeGraph()

        ops = [
            _make_op(0, "t0", OperationKind.READ, "x"),
            _make_op(1, "t1", OperationKind.READ, "x"),
        ]

        for op in ops:
            hb.add_operation(op)

        explorer = DPORExplorer(hb, {"t0": [0], "t1": [1]})

        schedules = explorer.explore()

        assert len(schedules) >= 1


class TestDPORMultiOp:
    """Multiple operations per thread."""

    def test_two_ops_per_thread(self):
        hb = HappensBeforeGraph()

        ops = [
            _make_op(0, "t0", OperationKind.WRITE, "x", "1"),
            _make_op(1, "t0", OperationKind.WRITE, "y", "2"),
            _make_op(2, "t1", OperationKind.READ, "x"),
            _make_op(3, "t1", OperationKind.READ, "y"),
        ]

        for op in ops:
            hb.add_operation(op)

        thread_ops = {"t0": [0, 1], "t1": [2, 3]}

        explorer = DPORExplorer(hb, thread_ops)

        schedules = explorer.explore()

        assert len(schedules) >= 1

        for sched in schedules:
            assert len(sched) == 4


class TestDPORBounding:
    """Max interleavings bound."""

    def test_max_interleavings(self):
        hb = HappensBeforeGraph()

        for i in range(6):
            op = _make_op(i, f"t{i % 2}", OperationKind.WRITE, "x", str(i))

            hb.add_operation(op)

        thread_ops = {
            "t0": [0, 2, 4],
            "t1": [1, 3, 5],
        }

        explorer = DPORExplorer(hb, thread_ops, max_interleavings=5)

        schedules = explorer.explore()

        assert len(schedules) <= 5


class TestRaceCandidates:
    """Race candidate detection."""

    def test_get_race_candidates(self):
        hb = HappensBeforeGraph()

        ops = [
            _make_op(0, "t0", OperationKind.WRITE, "x", "1"),
            _make_op(1, "t1", OperationKind.READ, "x"),
        ]

        for op in ops:
            hb.add_operation(op)

        explorer = DPORExplorer(hb, {"t0": [0], "t1": [1]})

        candidates = explorer.get_race_candidates()

        assert isinstance(candidates, list)


class TestConvenienceFunction:
    """Top-level explore_interleavings function."""

    def test_explore_interleavings(self):
        hb = HappensBeforeGraph()

        ops = [
            _make_op(0, "t0", OperationKind.WRITE, "shared", "a"),
            _make_op(1, "t1", OperationKind.WRITE, "shared", "b"),
        ]

        for op in ops:
            hb.add_operation(op)

        schedules = explore_interleavings(hb, {"t0": [0], "t1": [1]}, max_interleavings=100)

        assert len(schedules) >= 1
