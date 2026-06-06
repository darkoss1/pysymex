from pysymex.core.memory.heap.snapshots import MemorySnapshot
from pysymex.core.memory.heap.state import MemoryState
from pysymex.core.memory.heap.store import SymbolicHeap
from tests.unit.core.memory.heap_test_support import ensure_create_solver

ensure_create_solver()


class TestMemoryState:
    def test_push_frame(self) -> None:
        state = MemoryState()
        assert state.push_frame("f").function_name == "f"

    def test_pop_frame(self) -> None:
        state = MemoryState()
        state.push_frame("f")
        assert state.pop_frame() is not None

    def test_current_frame(self) -> None:
        state = MemoryState()
        state.push_frame("f")
        assert state.current_frame is not None

    def test_get_local(self) -> None:
        state = MemoryState()
        state.push_frame("f")
        state.set_local("x", 1)
        assert state.get_local("x") == 1

    def test_set_local(self) -> None:
        state = MemoryState()
        state.push_frame("f")
        state.set_local("x", 2)
        assert state.get_local("x") == 2

    def test_get_global(self) -> None:
        state = MemoryState()
        state.set_global("g", 1)
        assert state.get_global("g") == 1

    def test_set_global(self) -> None:
        state = MemoryState()
        state.set_global("g", 2)
        assert state.globals["g"] == 2

    def test_allocate_object(self) -> None:
        state = MemoryState()
        assert state.allocate_object("A").type_tag == "A"

    def test_read_field(self) -> None:
        state = MemoryState()
        addr = state.allocate_object("A")
        state.write_field(addr, "x", 3)
        assert state.read_field(addr, "x") is not None

    def test_write_field(self) -> None:
        state = MemoryState()
        addr = state.allocate_object("A")
        state.write_field(addr, "x", 3)
        assert state.heap.get_object(addr) is not None

    def test_snapshot(self) -> None:
        state = MemoryState()
        assert isinstance(state.snapshot(), MemorySnapshot)

    def test_restore(self) -> None:
        state = MemoryState()
        snap = state.snapshot()
        state.restore(snap)
        assert isinstance(state.heap, SymbolicHeap)


class TestMemorySnapshot:
    def test_initialization(self) -> None:
        snap = MemorySnapshot(MemoryState())
        assert isinstance(snap.globals, dict)
