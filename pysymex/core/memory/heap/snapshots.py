# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Detached snapshot payloads for symbolic heap and memory-state restoration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, TypedDict

import z3

from pysymex.core.memory.types import HeapObject, MemoryRegion, StackFrame, SymbolicAddress


class HeapSnapshotSource(Protocol):
    """Read interface consumed when copying the state of a symbolic heap."""

    @property
    def heap_data(self) -> dict[int, HeapObject]:
        """Return heap objects to copy into a snapshot."""
        ...

    @property
    def freed_set(self) -> set[int]:
        """Return freed addresses to copy into a snapshot."""
        ...

    @property
    def next_address_value(self) -> int:
        """Return the allocation counter value to capture."""
        ...

    @property
    def address_map_data(self) -> dict[int, SymbolicAddress]:
        """Return concrete-to-symbolic address metadata to copy."""
        ...

    @property
    def references_data(self) -> dict[int, set[str]]:
        """Return address-reference metadata to copy."""
        ...

    @property
    def z3_memory_data(self) -> dict[tuple[MemoryRegion, str], z3.ArrayRef]:
        """Return symbolic memory-array expressions to retain in a snapshot."""
        ...


class MemoryHeapSnapshotSource(Protocol):
    """Heap capability required to capture a complete memory snapshot."""

    def snapshot(self) -> HeapSnapshot:
        """Return a detached heap snapshot."""
        ...


class MemorySnapshotSource(Protocol):
    """Memory-state capability copied by :class:`MemorySnapshot`."""

    @property
    def heap(self) -> MemoryHeapSnapshotSource:
        """Return the heap source used for snapshot capture."""
        ...

    @property
    def globals(self) -> dict[str, object]:
        """Return global values to copy into a snapshot."""
        ...

    @property
    def stack(self) -> list[StackFrame]:
        """Return stack frames whose locals are copied into a snapshot."""
        ...


@dataclass
class HeapSnapshot:
    """Detached copy of heap objects, metadata, and symbolic memory arrays.

    Heap objects and mutable metadata containers are copied when captured.
    The stored Z3 array expressions are retained as immutable expression
    references for subsequent restore operations.
    """

    _heap: dict[int, HeapObject]
    _freed: set[int]
    _next_address: int
    _address_map: dict[int, SymbolicAddress]
    _references: dict[int, set[str]]
    _z3_memory: dict[tuple[MemoryRegion, str], z3.ArrayRef]

    def __init__(self, heap: HeapSnapshotSource):
        """Copy mutable heap records and metadata from ``heap``.

        Notes:
            Z3 array and address expressions are retained as expression
            references while containing dictionaries and object field maps are
            copied.
        """
        self._heap = {
            k: HeapObject(
                address=v.address,
                type_name=v.type_name,
                fields=dict(v.fields),
                is_mutable=v.is_mutable,
                size=v.size,
                is_alive=v.is_alive,
            )
            for k, v in heap.heap_data.items()
        }
        self._freed = set(heap.freed_set)
        self._next_address = heap.next_address_value
        self._address_map = dict(heap.address_map_data)
        self._references = {k: set(v) for k, v in heap.references_data.items()}
        self._z3_memory = dict(heap.z3_memory_data)

    @property
    def heap_data(self) -> dict[int, HeapObject]:
        """Return the snapshot's mutable copied heap-object mapping."""
        return self._heap

    @property
    def freed_set(self) -> set[int]:
        """Return the snapshot's mutable copied freed-address set."""
        return self._freed

    @property
    def next_address_value(self) -> int:
        """Return the captured next concrete allocation counter value."""
        return self._next_address

    @property
    def address_map_data(self) -> dict[int, SymbolicAddress]:
        """Return the snapshot's mutable copied address metadata mapping."""
        return self._address_map

    @property
    def references_data(self) -> dict[int, set[str]]:
        """Return the snapshot's mutable copied reference metadata mapping."""
        return self._references

    @property
    def z3_memory_data(self) -> dict[tuple[MemoryRegion, str], z3.ArrayRef]:
        """Return the snapshot's mutable copied symbolic-array mapping."""
        return self._z3_memory


class _FrameSnapshot(TypedDict):
    """Serializable portion of one captured symbolic stack frame."""

    function_name: str
    locals: dict[str, object]
    return_address: int | None


@dataclass
class MemorySnapshot:
    """Detached heap, global-store, and stack-frame snapshot."""

    heap_snapshot: HeapSnapshot
    globals: dict[str, object]
    stack_copies: list[_FrameSnapshot]

    def __init__(self, state: MemorySnapshotSource):
        """Capture heap, globals, and stack-local values from ``state``.

        Notes:
            Stack-frame parent links are reconstructed by
            :meth:`MemoryState.restore` from captured frame order rather than
            stored directly.
        """
        self.heap_snapshot = state.heap.snapshot()
        self.globals = dict(state.globals)
        self.stack_copies = []
        for frame in state.stack:
            self.stack_copies.append(
                {
                    "function_name": frame.function_name,
                    "locals": dict(frame.locals),
                    "return_address": frame.return_address,
                }
            )
