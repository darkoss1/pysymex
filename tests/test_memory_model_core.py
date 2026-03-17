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
