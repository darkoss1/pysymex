from typing import Any, cast

import z3

import pysymex.core.memory.heap as mod

heap_module = cast(Any, mod)
if not hasattr(heap_module, "create_solver"):
    setattr(heap_module, "create_solver", lambda: z3.Solver())


class TestSymbolicHeap:
    def test_allocate(self) -> None:
        heap = mod.SymbolicHeap()
        assert heap.allocate("obj").type_tag == "obj"

    def test_free(self) -> None:
        heap = mod.SymbolicHeap()
        addr = heap.allocate("obj")
        heap.free(addr)
        assert heap.get_object(addr) is None

    def test_read(self) -> None:
        heap = mod.SymbolicHeap()
        addr = heap.allocate("obj")
        heap.write(addr, 1)
        assert heap.read(addr) is not None

    def test_write(self) -> None:
        heap = mod.SymbolicHeap()
        addr = heap.allocate("obj")
        heap.write(addr, 1)
        assert heap.get_object(addr) is not None

    def test_get_object(self) -> None:
        heap = mod.SymbolicHeap()
        addr = heap.allocate("obj")
        assert heap.get_object(addr) is not None

    def test_fork(self) -> None:
        heap = mod.SymbolicHeap()
        child = heap.fork()
        assert child is not heap

    def test_add_reference(self) -> None:
        heap = mod.SymbolicHeap()
        addr = heap.allocate("obj")
        heap.add_reference(addr, "x")
        assert "x" in heap.get_references(addr)

    def test_remove_reference(self) -> None:
        heap = mod.SymbolicHeap()
        addr = heap.allocate("obj")
        heap.add_reference(addr, "x")
        heap.remove_reference(addr, "x")
        assert "x" not in heap.get_references(addr)

    def test_get_references(self) -> None:
        heap = mod.SymbolicHeap()
        addr = heap.allocate("obj")
        refs = heap.get_references(addr)
        assert isinstance(refs, set)

    def test_may_alias(self) -> None:
        heap = mod.SymbolicHeap()
        a = heap.allocate("obj")
        assert heap.may_alias(a, a)

    def test_must_alias(self) -> None:
        heap = mod.SymbolicHeap()
        a = heap.allocate("obj")
        assert heap.must_alias(a, a)

    def test_get_concrete_address(self) -> None:
        heap = mod.SymbolicHeap()
        a = heap.allocate("obj")
        assert heap.get_concrete_address(a) is not None

    def test_get_stats(self) -> None:
        heap = mod.SymbolicHeap()
        assert isinstance(heap.get_stats(), dict)

    def test_heap_data(self) -> None:
        heap = mod.SymbolicHeap()
        assert isinstance(heap.heap_data, dict)

    def test_freed_set(self) -> None:
        heap = mod.SymbolicHeap()
        assert isinstance(heap.freed_set, set)

    def test_next_address_value(self) -> None:
        heap = mod.SymbolicHeap()
        assert isinstance(heap.next_address_value, int)

    def test_snapshot(self) -> None:
        heap = mod.SymbolicHeap()
        assert isinstance(heap.snapshot(), mod.HeapSnapshot)

    def test_restore(self) -> None:
        heap = mod.SymbolicHeap()
        snap = heap.snapshot()
        heap.restore(snap)
        assert isinstance(heap.heap_data, dict)


class TestHeapSnapshot:
    def test_heap_data(self) -> None:
        snap = mod.SymbolicHeap().snapshot()
        assert isinstance(snap.heap_data, dict)

    def test_freed_set(self) -> None:
        snap = mod.SymbolicHeap().snapshot()
        assert isinstance(snap.freed_set, set)

    def test_next_address_value(self) -> None:
        snap = mod.SymbolicHeap().snapshot()
        assert isinstance(snap.next_address_value, int)


class TestMemoryState:
    def test_push_frame(self) -> None:
        state = mod.MemoryState()
        assert state.push_frame("f").function_name == "f"

    def test_pop_frame(self) -> None:
        state = mod.MemoryState()
        state.push_frame("f")
        assert state.pop_frame() is not None

    def test_current_frame(self) -> None:
        state = mod.MemoryState()
        state.push_frame("f")
        assert state.current_frame is not None

    def test_get_local(self) -> None:
        state = mod.MemoryState()
        state.push_frame("f")
        state.set_local("x", 1)
        assert state.get_local("x") == 1

    def test_set_local(self) -> None:
        state = mod.MemoryState()
        state.push_frame("f")
        state.set_local("x", 2)
        assert state.get_local("x") == 2

    def test_get_global(self) -> None:
        state = mod.MemoryState()
        state.set_global("g", 1)
        assert state.get_global("g") == 1

    def test_set_global(self) -> None:
        state = mod.MemoryState()
        state.set_global("g", 2)
        assert state.globals["g"] == 2

    def test_allocate_object(self) -> None:
        state = mod.MemoryState()
        assert state.allocate_object("A").type_tag == "A"

    def test_read_field(self) -> None:
        state = mod.MemoryState()
        addr = state.allocate_object("A")
        state.write_field(addr, "x", 3)
        assert state.read_field(addr, "x") is not None

    def test_write_field(self) -> None:
        state = mod.MemoryState()
        addr = state.allocate_object("A")
        state.write_field(addr, "x", 3)
        assert state.heap.get_object(addr) is not None

    def test_snapshot(self) -> None:
        state = mod.MemoryState()
        assert isinstance(state.snapshot(), mod.MemorySnapshot)

    def test_restore(self) -> None:
        state = mod.MemoryState()
        snap = state.snapshot()
        state.restore(snap)
        assert isinstance(state.heap, mod.SymbolicHeap)


class TestMemorySnapshot:
    def test_initialization(self) -> None:
        snap = mod.MemorySnapshot(mod.MemoryState())
        assert isinstance(snap.globals, dict)


class TestAliasingAnalyzer:
    def test_add_address(self) -> None:
        heap = mod.SymbolicHeap()
        a = heap.allocate("A")
        analyzer = mod.AliasingAnalyzer(heap)
        analyzer.add_address(a)
        assert len(analyzer.get_may_aliases(a)) >= 1

    def test_get_may_aliases(self) -> None:
        heap = mod.SymbolicHeap()
        a = heap.allocate("A")
        analyzer = mod.AliasingAnalyzer(heap)
        analyzer.add_address(a)
        assert isinstance(analyzer.get_may_aliases(a), set)

    def test_get_must_aliases(self) -> None:
        heap = mod.SymbolicHeap()
        a = heap.allocate("A")
        analyzer = mod.AliasingAnalyzer(heap)
        analyzer.add_address(a)
        assert isinstance(analyzer.get_must_aliases(a), set)

    def test_are_disjoint(self) -> None:
        heap = mod.SymbolicHeap()
        a = heap.allocate("A")
        b = heap.allocate("B")
        analyzer = mod.AliasingAnalyzer(heap)
        assert isinstance(analyzer.are_disjoint(a, b), bool)


class TestSymbolicArray:
    def test_length(self) -> None:
        arr = mod.SymbolicArray("a")
        assert z3.is_int(arr.length)

    def test_length_property(self) -> None:
        arr = mod.SymbolicArray("a")
        arr.length = z3.IntVal(4)
        assert z3.is_int_value(arr.length)

    def test_array(self) -> None:
        arr = mod.SymbolicArray("a")
        assert z3.is_array(arr.array)

    def test_get(self) -> None:
        arr = mod.SymbolicArray("a")
        assert z3.is_expr(arr.get(0))

    def test_set(self) -> None:
        arr = mod.SymbolicArray("a")
        assert isinstance(arr.set(0, z3.IntVal(1)), mod.SymbolicArray)

    def test_append(self) -> None:
        arr = mod.SymbolicArray("a")
        assert isinstance(arr.append(z3.IntVal(1)), mod.SymbolicArray)

    def test_get_constraints(self) -> None:
        arr = mod.SymbolicArray("a")
        assert isinstance(arr.get_constraints(), list)

    def test_add_constraint(self) -> None:
        arr = mod.SymbolicArray("a")
        arr.add_constraint(z3.BoolVal(True))
        assert len(arr.get_constraints()) >= 2

    def test_in_bounds(self) -> None:
        arr = mod.SymbolicArray("a")
        assert z3.is_bool(arr.in_bounds(0))


class TestSymbolicMap:
    def test_get(self) -> None:
        m = mod.SymbolicMap("m")
        assert z3.is_expr(m.get(z3.IntVal(1)))

    def test_set(self) -> None:
        m = mod.SymbolicMap("m")
        assert isinstance(m.set(z3.IntVal(1), z3.IntVal(2)), mod.SymbolicMap)

    def test_delete(self) -> None:
        m = mod.SymbolicMap("m")
        assert isinstance(m.delete(z3.IntVal(1)), mod.SymbolicMap)

    def test_contains(self) -> None:
        m = mod.SymbolicMap("m")
        assert z3.is_bool(m.contains(z3.IntVal(1)))

    def test_get_constraints(self) -> None:
        m = mod.SymbolicMap("m")
        assert isinstance(m.get_constraints(), list)

    def test_add_constraint(self) -> None:
        m = mod.SymbolicMap("m")
        m.add_constraint(z3.BoolVal(True))
        assert len(m.get_constraints()) == 1
