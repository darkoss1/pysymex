from importlib import import_module

import pysymex.core as core
from pysymex.core.memory.heap.state import MemoryState
from pysymex.core.memory.heap.store import SymbolicHeap
from pysymex.core.memory.types import HeapObject


def test_core_memory_exports_use_direct_owners() -> None:
    assert core.HeapObject is HeapObject
    assert core.SymbolicHeap is SymbolicHeap
    assert core.MemoryState is MemoryState


def test_memory_package_initializer_is_documentation_only() -> None:
    memory_package = import_module("pysymex.core.memory")

    assert "HeapObject" not in vars(memory_package)
    assert "SymbolicHeap" not in vars(memory_package)
    assert "MemoryState" not in vars(memory_package)
