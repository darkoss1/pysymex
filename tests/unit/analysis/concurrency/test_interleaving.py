import pytest
from pysymex.analysis.concurrency.interleaving import Transition, InterleavingState, DPORExplorer, explore_interleavings
from pysymex.analysis.concurrency import HappensBeforeGraph, MemoryOperation, OperationKind

class TestTransition:
    """Test suite for pysymex.analysis.concurrency.interleaving.Transition."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        op = MemoryOperation("t1", OperationKind.READ, "x")
        t = Transition("t1", op, 1)
        assert t.thread_id == "t1"
        assert t.op_id == 1
        assert t.operation is op
        assert t.enabled is True

class TestInterleavingState:
    """Test suite for pysymex.analysis.concurrency.interleaving.InterleavingState."""
    def test_clone(self) -> None:
        """Test clone behavior."""
        op = MemoryOperation("t1", OperationKind.READ, "x")
        state = InterleavingState(
            schedule=[Transition("t1", op, 1)],
            thread_states={"t1": 1},
            backtrack_set={"t2"},
            done_set={"t1"},
            sleep_set={"t3"}
        )
        cloned = state.clone()
        assert cloned.schedule == state.schedule
        assert cloned.thread_states == state.thread_states
        assert cloned.backtrack_set == state.backtrack_set
        
        # Verify it's a deep copy of collections
        cloned.backtrack_set.add("t4")
        assert "t4" not in state.backtrack_set

class TestDPORExplorer:
    """Test suite for pysymex.analysis.concurrency.interleaving.DPORExplorer."""
    def test_explore(self) -> None:
        """Test explore behavior."""
        hb = HappensBeforeGraph()
        op1 = MemoryOperation("t1", OperationKind.READ, "x")
        id1 = hb.add_operation(op1)
        thread_ops = {"t1": [id1]}
        
        explorer = DPORExplorer(hb, thread_ops)
        schedules = explorer.explore()
        assert len(schedules) == 1
        assert len(schedules[0]) == 1
        assert schedules[0][0].op_id == id1

    def test_get_race_candidates(self) -> None:
        """Test get_race_candidates behavior."""
        hb = HappensBeforeGraph()
        id1 = hb.add_operation(MemoryOperation("t1", OperationKind.WRITE, "x"))
        id2 = hb.add_operation(MemoryOperation("t2", OperationKind.READ, "x"))
        # Missing hb.add_program_order means they are fully concurrent
        explorer = DPORExplorer(hb, {"t1": [id1], "t2": [id2]})
        candidates = explorer.get_race_candidates()
        assert len(candidates) == 1
        assert candidates[0] == (id1, id2)

def test_explore_interleavings() -> None:
    """Test explore_interleavings behavior."""
    hb = HappensBeforeGraph()
    id1 = hb.add_operation(MemoryOperation("t1", OperationKind.READ, "x"))
    thread_ops = {"t1": [id1]}
    schedules = explore_interleavings(hb, thread_ops)
    assert len(schedules) == 1
