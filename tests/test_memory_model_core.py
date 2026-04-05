"""Tests for memory model core (core/memory_model_core.py)."""
from __future__ import annotations
import pytest
from pysymex.core.memory_model_core import (
    SymbolicHeap,
    HeapSnapshot,
    MemoryState,
    MemorySnapshot,
    AliasingAnalyzer,
    SymbolicArray,
    SymbolicMap,
)


class TestSymbolicHeap:
    def test_creation(self):
        heap = SymbolicHeap()
        assert heap is not None

    def test_allocate(self):
        heap = SymbolicHeap()
        addr = heap.allocate(type_name="object")
        assert addr is not None

    def test_read_write(self):
        heap = SymbolicHeap()
        addr = heap.allocate(type_name="object")
        heap.write(addr, 42)
        val = heap.read(addr)
        assert val is not None

    def test_snapshot(self):
        heap = SymbolicHeap()
        snap = heap.snapshot()
        assert snap is not None

    def test_fork_copy_on_write_isolation_child_write(self):
        heap = SymbolicHeap()
        addr = heap.allocate("obj")
        heap.write(addr, 10, "v")

        child = heap.fork()
        child.write(addr, 99, "v")

        assert heap.read(addr, "v") == 10
        assert child.read(addr, "v") == 99

    def test_fork_copy_on_write_isolation_parent_write(self):
        heap = SymbolicHeap()
        addr = heap.allocate("obj")
        heap.write(addr, 10, "v")

        child = heap.fork()
        heap.write(addr, 77, "v")

        assert heap.read(addr, "v") == 77
        assert child.read(addr, "v") == 10

    def test_fork_reports_shared_objects(self):
        heap = SymbolicHeap()
        heap.write(heap.allocate("obj"), 1, "v")
        heap.write(heap.allocate("obj"), 2, "v")
        child = heap.fork()

        parent_stats = heap.get_stats()
        child_stats = child.get_stats()
        assert parent_stats["shared_object_count"] >= 2
        assert child_stats["shared_object_count"] >= 2


class TestHeapSnapshot:
    def test_creation(self):
        heap = SymbolicHeap()
        snap = HeapSnapshot(heap)
        assert snap is not None


class TestMemoryState:
    def test_creation(self):
        ms = MemoryState()
        assert ms is not None

    def test_has_heap(self):
        ms = MemoryState()
        assert hasattr(ms, 'heap') or hasattr(ms, '_heap')


class TestMemorySnapshot:
    def test_creation(self):
        ms = MemoryState()
        snap = MemorySnapshot(ms)
        assert snap is not None


class TestAliasingAnalyzer:
    def test_creation(self):
        heap = SymbolicHeap()
        aa = AliasingAnalyzer(heap)
        assert aa is not None

    def test_has_analyze(self):
        assert hasattr(AliasingAnalyzer, 'may_alias') or hasattr(AliasingAnalyzer, 'get_may_aliases') or hasattr(AliasingAnalyzer, 'analyze')
    
        def test_concrete_fast_path_returns_bucket(self):
            heap = SymbolicHeap()
            aa = AliasingAnalyzer(heap)
            a1 = heap.allocate("obj")
            a2 = SymbolicAddress(MemoryRegion.HEAP, base=a1.base)
            aa.add_address(a1)
            aa.add_address(a2)

            may_aliases = aa.get_may_aliases(a1)
            must_aliases = aa.get_must_aliases(a1)

            assert a1 in may_aliases
            assert a2 in may_aliases
            assert a1 in must_aliases
            assert a2 in must_aliases

        def test_query_cache_invalidated_on_new_address(self):
            heap = SymbolicHeap()
            aa = AliasingAnalyzer(heap)
            a1 = heap.allocate("obj")
            aa.add_address(a1)

            # Populate caches by querying aliases.
            _ = aa.get_may_aliases(a1)
            _ = aa.get_must_aliases(a1)

            # Add same-concrete alias and ensure updated result is visible.
            a2 = SymbolicAddress(MemoryRegion.HEAP, base=a1.base)
            aa.add_address(a2)
            may_aliases = aa.get_may_aliases(a1)
            must_aliases = aa.get_must_aliases(a1)

            assert a2 in may_aliases
            assert a2 in must_aliases


class TestSymbolicArray:
    def test_creation(self):
        arr = SymbolicArray("arr")
        assert arr is not None

    def test_has_select_store(self):
        arr = SymbolicArray("arr")
        assert hasattr(arr, 'get') or hasattr(arr, 'select') or hasattr(arr, 'read') or hasattr(arr, '__getitem__')
        assert hasattr(arr, 'set') or hasattr(arr, 'store') or hasattr(arr, 'write') or hasattr(arr, '__setitem__')


class TestSymbolicMap:
    def test_creation(self):
        m = SymbolicMap("map")
        assert m is not None

    def test_has_get_put(self):
        m = SymbolicMap("map")
        assert hasattr(m, 'get') or hasattr(m, 'select') or hasattr(m, '__getitem__')
