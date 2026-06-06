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

"""Concrete-object and symbolic-array storage for one memory state."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.core.memory.heap.symbolic_access import SymbolicHeapAccessMixin
from pysymex.core.memory.types import HeapObject, MemoryRegion, SymbolicAddress
from pysymex.core.solver.constraints.simplification import simplify_bool_expr
from pysymex.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from pysymex.core.memory.heap.snapshots import HeapSnapshot


class SymbolicHeap(SymbolicHeapAccessMixin):
    """Store heap objects and symbolic field arrays for one memory state.

    Concrete addresses index ``HeapObject`` instances. Symbolic-address reads
    and writes delegate to the Z3-array operations in
    :class:`SymbolicHeapAccessMixin`, while may/must alias policy is inherited
    through the access mixin. A fork shares heap objects until a concrete write
    requests an object-level copy.

    Notes:
        Symbolic frees constrain liveness for possible target objects; they do
        not concretely delete an object without a resolved address.
    """

    def __init__(self) -> None:
        """Initialize empty heap maps, symbolic arrays, caches, and counters."""
        self._next_address: int = 1000
        self._heap: dict[int, HeapObject] = {}
        self._address_map: dict[int, SymbolicAddress] = {}
        self._references: dict[int, set[str]] = {}
        self._freed: set[int] = set()
        self._symbolic_candidate_cache: dict[tuple[MemoryRegion, str], list[int]] = {}
        self._z3_memory: dict[tuple[MemoryRegion, str], z3.ArrayRef] = {}
        self._allocations = 0
        self._frees = 0
        self._reads = 0
        self._writes = 0
        self._symbolic_reads = 0
        self._symbolic_writes = 0
        self._candidate_cache_hits = 0
        self._candidate_cache_misses = 0
        self._peak_live_objects = 0
        self._symbolic_candidate_cache_limit = 512
        self._shared_object_addrs: set[int] = set()

    @staticmethod
    def _clone_heap_object(obj: HeapObject) -> HeapObject:
        """Copy mutable object fields while retaining symbolic metadata references."""
        return HeapObject(
            address=obj.address,
            type_name=obj.type_name,
            fields=dict(obj.fields),
            is_mutable=obj.is_mutable,
            size=obj.size,
            is_alive=obj.is_alive,
        )

    def _ensure_unshared_object(self, addr: int) -> None:
        """Clone a shared concrete object before this heap mutates it."""
        if addr not in self._shared_object_addrs:
            return
        obj = self._heap.get(addr)
        if obj is None:
            self._shared_object_addrs.discard(addr)
            return
        self._heap[addr] = self._clone_heap_object(obj)
        self._shared_object_addrs.discard(addr)

    def allocate(
        self,
        type_name: str = "object",
        size: int = 1,
        is_mutable: bool = True,
        region: MemoryRegion = MemoryRegion.HEAP,
    ) -> SymbolicAddress:
        """Allocate a concrete-backed object and return its symbolic address.

        Side Effects:
            Advances the address counter, registers heap metadata, and clears
            symbolic candidate caches.
        """
        addr = self._next_address
        self._next_address += size
        sym_addr = SymbolicAddress(region=region, base=addr, offset=0, type_tag=type_name)
        obj = HeapObject(address=sym_addr, type_name=type_name, is_mutable=is_mutable, size=size)
        self._heap[addr] = obj
        self._address_map[addr] = sym_addr
        self._references[addr] = set()
        self._symbolic_candidate_cache.clear()
        self._allocations += 1
        self._peak_live_objects = max(self._peak_live_objects, len(self._heap))
        return sym_addr

    def free(self, address: SymbolicAddress) -> None:
        """Apply concrete deallocation or symbolic liveness restriction.

        Raises:
            ValueError: If a concrete address is already freed or was not allocated.

        Notes:
            A symbolic address updates candidate liveness formulas for possible
            aliases; it does not choose and delete a concrete object.
        """
        addr = self._get_concrete_address(address)
        if addr is None:
            for obj in self._heap.values():
                if obj.address.region != address.region:
                    continue
                cond = address.effective_address == obj.address.effective_address
                if not self._may_alias(cond):
                    continue
                obj.is_alive = simplify_bool_expr(z3.And(obj.is_alive, z3.Not(cond)))
            return
        if addr in self._freed:
            raise ValueError(f"Double free detected at address {addr}")
        if addr not in self._heap:
            raise ValueError(f"Freeing unallocated address {addr}")
        self._ensure_unshared_object(addr)
        self._freed.add(addr)
        del self._heap[addr]
        del self._address_map[addr]
        if addr in self._references:
            del self._references[addr]
        self._shared_object_addrs.discard(addr)
        self._symbolic_candidate_cache.clear()
        self._frees += 1

    def read(self, address: SymbolicAddress, field: str = "__value__") -> object:
        """Read a concrete field or construct a symbolic-array selection.

        Raises:
            ValueError: If a resolved concrete address has already been freed.
        """
        self._reads += 1
        addr = self._get_concrete_address(address)
        if addr is None:
            self._symbolic_reads += 1
            return self._read_symbolic(address, field)
        if addr in self._freed:
            raise ValueError(f"Use after free detected at address {addr}")
        if addr not in self._heap:
            return SymbolicValue.from_const(None)
        obj = self._heap[addr]
        return obj.get_field(field)

    def write(self, address: SymbolicAddress, value: object, field: str = "__value__") -> None:
        """Write a concrete field or update a symbolic field array.

        Side Effects:
            Concrete writes clone a shared object before mutation. Symbolic
            writes update the Z3 memory array for the address region and field.
            A concrete address absent from the heap creates a mutable object
            record at that address before storing the field.

        Raises:
            ValueError: If a resolved concrete address has already been freed,
                or an immutable heap object rejects field mutation.
        """
        self._writes += 1
        addr = self._get_concrete_address(address)
        if addr is None:
            self._symbolic_writes += 1
            self._write_symbolic(address, value, field)
            return
        if addr in self._freed:
            raise ValueError(f"Write to freed memory at address {addr}")
        if addr not in self._heap:
            sym_addr = self._address_map.get(addr, address)
            obj = HeapObject(address=sym_addr, type_name=address.type_tag, is_mutable=True)
            self._heap[addr] = obj
            self._references[addr] = set()
            self._shared_object_addrs.discard(addr)
        else:
            self._ensure_unshared_object(addr)
        stored_value = (
            self._as_symbolic_value(value, f"mem_store_{field}")
            if isinstance(value, SymbolicValue | bool | int | float | str)
            else value
        )
        self._heap[addr].set_field(field, stored_value)

    def get_object(self, address: SymbolicAddress) -> HeapObject | None:
        """Return the concrete-backed heap object for a resolved address, if present."""
        addr = self._get_concrete_address(address)
        if addr is None:
            return None
        return self._heap.get(addr)

    def fork(self) -> SymbolicHeap:
        """Fork heap metadata while sharing object records until concrete mutation.

        Notes:
            Parent and child mark live concrete objects as shared and clone an
            object before a subsequent concrete write or free. Z3 expression
            objects are retained as symbolic values rather than deep-copied.
        """
        child = SymbolicHeap()
        child._next_address = self._next_address
        child._heap = dict(self._heap)
        child._address_map = dict(self._address_map)
        child._references = {k: set(v) for k, v in self._references.items()}
        child._freed = set(self._freed)
        child._symbolic_candidate_cache = {
            k: list(v) for k, v in self._symbolic_candidate_cache.items()
        }
        child._z3_memory = dict(self._z3_memory)
        child._allocations = self._allocations
        child._frees = self._frees
        child._reads = self._reads
        child._writes = self._writes
        child._symbolic_reads = self._symbolic_reads
        child._symbolic_writes = self._symbolic_writes
        child._candidate_cache_hits = self._candidate_cache_hits
        child._candidate_cache_misses = self._candidate_cache_misses
        child._peak_live_objects = self._peak_live_objects
        child._shared_object_addrs = set(child._heap.keys())
        self._shared_object_addrs.update(self._heap.keys())
        return child

    def add_reference(self, address: SymbolicAddress, var_name: str) -> None:
        """Record a variable reference when ``address`` resolves to a tracked object."""
        addr = self._get_concrete_address(address)
        if addr is not None and addr in self._references:
            self._references[addr].add(var_name)

    def remove_reference(self, address: SymbolicAddress, var_name: str) -> None:
        """Discard a recorded reference when ``address`` resolves to a tracked object."""
        addr = self._get_concrete_address(address)
        if addr is not None and addr in self._references:
            self._references[addr].discard(var_name)

    def get_references(self, address: SymbolicAddress) -> set[str]:
        """Return a copy of tracked reference names for a concrete address."""
        addr = self._get_concrete_address(address)
        if addr is None:
            return set()
        return set(self._references.get(addr, ()))

    def get_stats(self) -> dict[str, int]:
        """Return lightweight runtime counters for performance diagnostics."""
        return {
            "allocations": self._allocations,
            "frees": self._frees,
            "reads": self._reads,
            "writes": self._writes,
            "symbolic_reads": self._symbolic_reads,
            "symbolic_writes": self._symbolic_writes,
            "candidate_cache_hits": self._candidate_cache_hits,
            "candidate_cache_misses": self._candidate_cache_misses,
            "candidate_cache_entries": len(self._symbolic_candidate_cache),
            "candidate_cache_limit": self._symbolic_candidate_cache_limit,
            "shared_object_count": len(self._shared_object_addrs),
            "live_objects": len(self._heap),
            "peak_live_objects": self._peak_live_objects,
        }

    @property
    def heap_data(self) -> dict[int, HeapObject]:
        """Return the mutable internal mapping of concrete heap objects."""
        return self._heap

    @property
    def freed_set(self) -> set[int]:
        """Return the mutable internal set of freed concrete addresses."""
        return self._freed

    @property
    def next_address_value(self) -> int:
        """Return the next concrete allocation counter value."""
        return self._next_address

    @property
    def address_map_data(self) -> dict[int, SymbolicAddress]:
        """Return the mutable internal concrete-to-symbolic address mapping."""
        return self._address_map

    @property
    def references_data(self) -> dict[int, set[str]]:
        """Return the mutable internal heap-reference metadata mapping."""
        return self._references

    @property
    def z3_memory_data(self) -> dict[tuple[MemoryRegion, str], z3.ArrayRef]:
        """Return the mutable internal symbolic-array mapping."""
        return self._z3_memory

    def snapshot(self) -> HeapSnapshot:
        """Capture detached mutable heap metadata in a :class:`HeapSnapshot`."""
        from pysymex.core.memory.heap.snapshots import HeapSnapshot

        return HeapSnapshot(self)

    def restore(self, snapshot: HeapSnapshot) -> None:
        """Replace heap maps from a captured snapshot and clear candidate caches."""
        self._heap = {k: self._clone_heap_object(v) for k, v in snapshot.heap_data.items()}
        self._freed = set(snapshot.freed_set)
        self._next_address = snapshot.next_address_value
        self._address_map = dict(snapshot.address_map_data)
        self._references = {k: set(v) for k, v in snapshot.references_data.items()}
        self._z3_memory = dict(snapshot.z3_memory_data)
        self._symbolic_candidate_cache.clear()
        self._shared_object_addrs.clear()
        self._peak_live_objects = max(self._peak_live_objects, len(self._heap))

    def __repr__(self) -> str:
        """Return a diagnostic summary of heap population and allocation state."""
        return f"SymbolicHeap({len(self._heap)} objects, next_addr={self._next_address})"
