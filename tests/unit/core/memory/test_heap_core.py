import time

import z3

from pysymex.core.memory.heap.snapshots import HeapSnapshot
from pysymex.core.memory.heap.store import SymbolicHeap
from pysymex.core.memory.alias_queries import AliasQueryStatus
from pysymex.core.memory.types import MemoryRegion, SymbolicAddress
from pysymex.core.solver.engine.context import active_incremental_solver
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.types.scalars.values import SymbolicValue
from tests.unit.core.memory.heap_test_support import ensure_create_solver

ensure_create_solver()


class TestSymbolicHeap:
    def test_allocate(self) -> None:
        heap = SymbolicHeap()
        assert heap.allocate("obj").type_tag == "obj"

    def test_free(self) -> None:
        heap = SymbolicHeap()
        addr = heap.allocate("obj")
        heap.free(addr)
        assert heap.get_object(addr) is None

    def test_read(self) -> None:
        heap = SymbolicHeap()
        addr = heap.allocate("obj")
        heap.write(addr, 1)
        assert heap.read(addr) is not None

    def test_write(self) -> None:
        heap = SymbolicHeap()
        addr = heap.allocate("obj")
        heap.write(addr, 1)
        assert heap.get_object(addr) is not None

    def test_get_object(self) -> None:
        heap = SymbolicHeap()
        addr = heap.allocate("obj")
        assert heap.get_object(addr) is not None

    def test_fork(self) -> None:
        heap = SymbolicHeap()
        child = heap.fork()
        assert child is not heap

    def test_add_reference(self) -> None:
        heap = SymbolicHeap()
        addr = heap.allocate("obj")
        heap.add_reference(addr, "x")
        assert "x" in heap.get_references(addr)

    def test_remove_reference(self) -> None:
        heap = SymbolicHeap()
        addr = heap.allocate("obj")
        heap.add_reference(addr, "x")
        heap.remove_reference(addr, "x")
        assert "x" not in heap.get_references(addr)

    def test_get_references(self) -> None:
        heap = SymbolicHeap()
        addr = heap.allocate("obj")
        refs = heap.get_references(addr)
        assert isinstance(refs, set)

    def test_may_alias(self) -> None:
        heap = SymbolicHeap()
        a = heap.allocate("obj")
        assert heap.may_alias(a, a)

    def test_may_alias_result_reports_established_same_address(self) -> None:
        heap = SymbolicHeap()
        a = heap.allocate("obj")

        result = heap.may_alias_result(a, a)

        assert result.status is AliasQueryStatus.ESTABLISHED
        assert result.is_established
        assert result.reason is None

    def test_may_alias_result_refutes_different_regions(self) -> None:
        heap = SymbolicHeap()
        a = SymbolicAddress(MemoryRegion.HEAP, 1)
        b = SymbolicAddress(MemoryRegion.GLOBAL, 1)

        result = heap.may_alias_result(a, b)

        assert result.status is AliasQueryStatus.REFUTED
        assert not result.is_established
        assert result.reason == "different_regions"

    def test_must_alias(self) -> None:
        heap = SymbolicHeap()
        a = heap.allocate("obj")
        assert heap.must_alias(a, a)

    def test_must_alias_result_reports_established_same_address(self) -> None:
        heap = SymbolicHeap()
        a = heap.allocate("obj")

        result = heap.must_alias_result(a, a)

        assert result.status is AliasQueryStatus.ESTABLISHED
        assert result.is_established
        assert result.reason is None

    def test_alias_queries_preserve_unknown_soundness_with_active_solver(self) -> None:
        heap = SymbolicHeap()
        a = SymbolicAddress(MemoryRegion.HEAP, z3.BitVec("active_unknown_alias_a", 64))
        b = SymbolicAddress(MemoryRegion.HEAP, z3.BitVec("active_unknown_alias_b", 64))
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)
        token = active_incremental_solver.set(solver)
        try:
            may_alias = heap.may_alias(a, b)
            must_alias = heap.must_alias(a, b)
            may_result = heap.may_alias_result(a, b)
            must_result = heap.must_alias_result(a, b)
        finally:
            active_incremental_solver.reset(token)

        assert may_alias is True
        assert must_alias is False
        assert may_result.status is AliasQueryStatus.UNKNOWN
        assert may_result.is_unknown
        assert may_result.reason == "solver_unknown"
        assert must_result.status is AliasQueryStatus.UNKNOWN
        assert must_result.is_unknown
        assert must_result.reason == "solver_unknown"

    def test_get_stats(self) -> None:
        heap = SymbolicHeap()
        assert isinstance(heap.get_stats(), dict)

    def test_heap_data(self) -> None:
        heap = SymbolicHeap()
        assert isinstance(heap.heap_data, dict)

    def test_freed_set(self) -> None:
        heap = SymbolicHeap()
        assert isinstance(heap.freed_set, set)

    def test_next_address_value(self) -> None:
        heap = SymbolicHeap()
        assert isinstance(heap.next_address_value, int)

    def test_snapshot(self) -> None:
        heap = SymbolicHeap()
        assert isinstance(heap.snapshot(), HeapSnapshot)

    def test_restore(self) -> None:
        heap = SymbolicHeap()
        snap = heap.snapshot()
        heap.restore(snap)
        assert isinstance(heap.heap_data, dict)

    def test_restore_restores_references(self) -> None:
        heap = SymbolicHeap()
        addr = heap.allocate("obj")
        heap.add_reference(addr, "x")
        snap = heap.snapshot()

        heap.remove_reference(addr, "x")
        heap.restore(snap)

        assert heap.get_references(addr) == {"x"}

    def test_restore_restores_address_map_for_later_free(self) -> None:
        heap = SymbolicHeap()
        addr = heap.allocate("obj")
        snap = heap.snapshot()

        heap.free(addr)
        heap.restore(snap)
        heap.free(addr)

        assert heap.get_object(addr) is None

    def test_restore_rolls_back_symbolic_memory_array(self) -> None:
        heap = SymbolicHeap()
        addr = SymbolicAddress(MemoryRegion.HEAP, z3.BitVec("heap_restore_addr", 64))
        before = heap.read(addr, "value")
        assert isinstance(before, SymbolicValue)
        snap = heap.snapshot()

        heap.write(addr, 42, "value")
        heap.restore(snap)
        after = heap.read(addr, "value")

        assert isinstance(after, SymbolicValue)
        assert z3.eq(before.z3_int, after.z3_int)

    def test_restore_restores_symbolic_liveness(self) -> None:
        heap = SymbolicHeap()
        addr = heap.allocate("obj")
        obj = heap.get_object(addr)
        assert obj is not None
        obj.is_alive = z3.Bool("heap_restore_alive")
        snap = heap.snapshot()

        obj.is_alive = z3.BoolVal(False)
        heap.restore(snap)
        restored = heap.get_object(addr)

        assert restored is not None
        assert z3.eq(restored.is_alive, z3.Bool("heap_restore_alive"))


class TestHeapSnapshot:
    def test_heap_data(self) -> None:
        snap = SymbolicHeap().snapshot()
        assert isinstance(snap.heap_data, dict)

    def test_freed_set(self) -> None:
        snap = SymbolicHeap().snapshot()
        assert isinstance(snap.freed_set, set)

    def test_next_address_value(self) -> None:
        snap = SymbolicHeap().snapshot()
        assert isinstance(snap.next_address_value, int)
