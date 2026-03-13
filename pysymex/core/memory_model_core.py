"""
pysymex Memory Model - Core logic classes
Provides symbolic heap modeling, memory state management, aliasing analysis,
and symbolic collection types.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import cast

import z3

logger = logging.getLogger(__name__)

from pysymex.core.addressing import next_address
from pysymex.core.memory_model_types import (
    HeapObject,
    MemoryRegion,
    StackFrame,
    SymbolicAddress,
)
from pysymex.core.solver import create_solver

from .symbolic_types import SymbolicInt


class SymbolicHeap:
    """
    The central memory management system for pysymex.
    Manages:
    - Heap allocation and deallocation
    - Object field access
    - Reference tracking
    - Garbage collection hints
    """

    def __init__(self):
        """Init."""
        """Initialize the class instance."""
        self._next_address = 1000
        self._heap: dict[int, HeapObject] = {}
        self._address_map: dict[int, SymbolicAddress] = {}
        self._references: dict[int, set[str]] = {}
        self._freed: set[int] = set()
        self._solver = create_solver()

    def allocate(
        self,
        type_name: str,
        size: int = 1,
        is_mutable: bool = True,
        region: MemoryRegion = MemoryRegion.HEAP,
    ) -> SymbolicAddress:
        """
        Allocate a new object on the heap.
        Args:
            type_name: The Python type name of the object
            size: Number of slots in the object
            is_mutable: Whether the object can be modified
            region: Which memory region to allocate in
        Returns:
            A SymbolicAddress pointing to the new object
        """
        addr = self._next_address
        self._next_address += size
        sym_addr = SymbolicAddress(region=region, base=addr, offset=0, type_tag=type_name)
        obj = HeapObject(address=sym_addr, type_name=type_name, is_mutable=is_mutable, size=size)
        self._heap[addr] = obj
        self._address_map[addr] = sym_addr
        self._references[addr] = set()
        return sym_addr

    def free(self, address: SymbolicAddress) -> None:
        """
        Free an allocated object.
        Note: Python uses garbage collection, so this is mainly for
        modeling C extensions or explicit resource management.
        """
        addr = self._get_concrete_address(address)
        if addr is None:
            return
        if addr in self._freed:
            raise ValueError(f"Double free detected at address {addr}")
        if addr not in self._heap:
            raise ValueError(f"Freeing unallocated address {addr}")
        self._freed.add(addr)
        del self._heap[addr]
        del self._address_map[addr]
        if addr in self._references:
            del self._references[addr]

    def read(self, address: SymbolicAddress, field: str = "__value__") -> object:
        """
        Read a value from memory.
        Args:
            address: The symbolic address to read from
            field: The field name to read (default is __value__ for simple values)
        Returns:
            The value at the address, or a fresh symbolic if unknown
        """
        addr = self._get_concrete_address(address)
        if addr is None:
            return SymbolicInt(z3.Int(f"mem_read_{next_address ()}_{field}"))
        if addr in self._freed:
            raise ValueError(f"Use after free detected at address {addr}")
        if addr not in self._heap:
            return SymbolicInt(z3.Int(f"uninit_{addr}_{field}"))
        obj = self._heap[addr]
        return obj.get_field(field)

    def write(self, address: SymbolicAddress, value: object, field: str = "__value__") -> None:
        """
        Write a value to memory.
        Args:
            address: The symbolic address to write to
            value: The value to write
            field: The field name to write (default is __value__ for simple values)
        """
        addr = self._get_concrete_address(address)
        if addr is None:
            addr = self._next_address
            self._next_address += 1
            sym_addr = SymbolicAddress(
                region=address.region, base=addr, offset=0, type_tag=address.type_tag
            )
            obj = HeapObject(address=sym_addr, type_name=address.type_tag, is_mutable=True)
            self._heap[addr] = obj
            self._address_map[addr] = sym_addr
            self._references[addr] = set()
        if addr in self._freed:
            raise ValueError(f"Write to freed memory at address {addr}")
        if addr not in self._heap:
            sym_addr = self._address_map.get(addr, address)
            obj = HeapObject(address=sym_addr, type_name=address.type_tag, is_mutable=True)
            self._heap[addr] = obj
            self._references[addr] = set()
        self._heap[addr].set_field(field, value)

    def get_object(self, address: SymbolicAddress) -> HeapObject | None:
        """Get the heap object at an address."""
        addr = self._get_concrete_address(address)
        if addr is None:
            return None
        return self._heap.get(addr)

    def add_reference(self, address: SymbolicAddress, var_name: str) -> None:
        """Record that a variable references this address."""
        addr = self._get_concrete_address(address)
        if addr is not None and addr in self._references:
            self._references[addr].add(var_name)

    def remove_reference(self, address: SymbolicAddress, var_name: str) -> None:
        """Remove a variable's reference to this address."""
        addr = self._get_concrete_address(address)
        if addr is not None and addr in self._references:
            self._references[addr].discard(var_name)

    def get_references(self, address: SymbolicAddress) -> set[str]:
        """Get all variables referencing this address."""
        addr = self._get_concrete_address(address)
        if addr is None:
            return set()
        return self._references.get(addr, set()).copy()

    def may_alias(self, addr1: SymbolicAddress, addr2: SymbolicAddress) -> bool:
        """Check if two addresses may refer to the same location."""
        return addr1.may_alias(addr2, self._solver)

    def must_alias(self, addr1: SymbolicAddress, addr2: SymbolicAddress) -> bool:
        """Check if two addresses must refer to the same location."""
        return addr1.must_alias(addr2, self._solver)

    def _get_concrete_address(self, address: SymbolicAddress) -> int | None:
        """
        Try to get a concrete address value.
        Returns None if the address is truly symbolic.
        """
        try:
            if z3.is_bv_value(address.base) and z3.is_bv_value(address.offset):
                base = address.base.as_long()
                offset = address.offset.as_long()
                return base + offset
        except z3.Z3Exception:
            logger.debug("Failed to resolve concrete address", exc_info=True)
        return None

    def get_concrete_address(self, address: SymbolicAddress) -> int | None:
        """Public access to concrete address resolution."""
        return self._get_concrete_address(address)

    @property
    def heap_data(self) -> dict[int, HeapObject]:
        """Public read access to heap objects."""
        return self._heap

    @property
    def freed_set(self) -> set[int]:
        """Public read access to freed addresses."""
        return self._freed

    @property
    def next_address_value(self) -> int:
        """Public read access to next address counter."""
        return self._next_address

    def snapshot(self) -> HeapSnapshot:
        """Create a snapshot of the current heap state."""
        return HeapSnapshot(self)

    def restore(self, snapshot: HeapSnapshot) -> None:
        """Restore the heap to a previous state."""
        self._heap = {
            k: HeapObject(
                address=v.address,
                type_name=v.type_name,
                fields=dict(v.fields),
                is_mutable=v.is_mutable,
                size=v.size,
            )
            for k, v in snapshot.heap_data.items()
        }
        self._freed = set(snapshot.freed_set)
        self._next_address = snapshot.next_address_value

    def __repr__(self) -> str:
        """Repr."""
        """Return a formal string representation."""
        return f"SymbolicHeap({len (self._heap )} objects, next_addr={self._next_address})"


@dataclass
class HeapSnapshot:
    """A snapshot of heap state for backtracking during symbolic execution."""

    _heap: dict[int, HeapObject]
    _freed: set[int]
    _next_address: int

    def __init__(self, heap: SymbolicHeap):
        """Init."""
        """Initialize the class instance."""
        self._heap = {
            k: HeapObject(
                address=v.address,
                type_name=v.type_name,
                fields=dict(v.fields),
                is_mutable=v.is_mutable,
                size=v.size,
            )
            for k, v in heap.heap_data.items()
        }
        self._freed = set(heap.freed_set)
        self._next_address = heap.next_address_value

    @property
    def heap_data(self) -> dict[int, HeapObject]:
        """Public read access to heap objects."""
        return self._heap

    @property
    def freed_set(self) -> set[int]:
        """Public read access to freed addresses."""
        return self._freed

    @property
    def next_address_value(self) -> int:
        """Public read access to next address counter."""
        return self._next_address


class MemoryState:
    """
    Unified memory state combining stack, heap, and globals.
    This is the main interface used by the VM for memory operations.
    """

    def __init__(self):
        """Init."""
        """Initialize the class instance."""
        self.heap = SymbolicHeap()
        self.globals: dict[str, object] = {}
        self.stack: list[StackFrame] = []
        self._current_frame: StackFrame | None = None

    def push_frame(self, function_name: str) -> StackFrame:
        """Push a new stack frame for a function call."""
        frame = StackFrame(function_name=function_name, parent_frame=self._current_frame)
        self.stack.append(frame)
        self._current_frame = frame
        return frame

    def pop_frame(self) -> StackFrame | None:
        """Pop the current stack frame after a function returns."""
        if not self.stack:
            return None
        frame = self.stack.pop()
        self._current_frame = frame.parent_frame
        return frame

    @property
    def current_frame(self) -> StackFrame | None:
        """Get the current (topmost) stack frame."""
        return self._current_frame

    def get_local(self, name: str) -> object:
        """Get a local variable from the current frame."""
        if self._current_frame:
            return self._current_frame.get_local(name)
        return None

    def set_local(self, name: str, value: object) -> None:
        """Set a local variable in the current frame."""
        if self._current_frame:
            self._current_frame.set_local(name, value)

    def get_global(self, name: str) -> object:
        """Get a global variable."""
        return self.globals.get(name)

    def set_global(self, name: str, value: object) -> None:
        """Set a global variable."""
        self.globals[name] = value

    def allocate_object(
        self,
        type_name: str,
        initial_fields: dict[str, object] | None = None,
        is_mutable: bool = True,
    ) -> SymbolicAddress:
        """Allocate a new object and optionally initialize fields."""
        addr = self.heap.allocate(type_name, is_mutable=is_mutable)
        if initial_fields:
            obj = self.heap.get_object(addr)
            if obj:
                for name, value in initial_fields.items():
                    obj.set_field(name, value)
        return addr

    def read_field(self, address: SymbolicAddress, field: str) -> object:
        """Read a field from an object."""
        return self.heap.read(address, field)

    def write_field(self, address: SymbolicAddress, field: str, value: object) -> None:
        """Write a field to an object."""
        self.heap.write(address, value, field)

    def snapshot(self) -> MemorySnapshot:
        """Create a snapshot of the entire memory state."""
        return MemorySnapshot(self)

    def restore(self, snapshot: MemorySnapshot) -> None:
        """Restore memory to a previous state."""
        self.heap.restore(snapshot.heap_snapshot)
        self.globals = dict(snapshot.globals)
        self.stack = []
        prev_frame = None
        for frame_copy in snapshot.stack_copies:
            frame = StackFrame(
                function_name=frame_copy["function_name"],
                locals=dict(frame_copy["locals"]),
                return_address=frame_copy["return_address"],
                parent_frame=prev_frame,
            )
            self.stack.append(frame)
            prev_frame = frame
        self._current_frame = self.stack[-1] if self.stack else None


@dataclass
class MemorySnapshot:
    """Complete memory state snapshot."""

    heap_snapshot: HeapSnapshot
    globals: dict[str, object]
    stack_copies: list[dict[str, object]]

    def __init__(self, state: MemoryState):
        """Init."""
        """Initialize the class instance."""
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


class AliasingAnalyzer:
    """
    Performs alias analysis on symbolic memory.
    Determines which pointers may or must point to the same memory location.
    """

    def __init__(self, heap: SymbolicHeap):
        """Init."""
        """Initialize the class instance."""
        self.heap = heap
        self._alias_sets: dict[int, set[SymbolicAddress]] = {}

    def add_address(self, addr: SymbolicAddress) -> None:
        """Add an address to the analysis."""
        concrete = self.heap.get_concrete_address(addr)
        if concrete is not None:
            if concrete not in self._alias_sets:
                self._alias_sets[concrete] = set()
            self._alias_sets[concrete].add(addr)

    def get_may_aliases(self, addr: SymbolicAddress) -> set[SymbolicAddress]:
        """Get all addresses that may alias with the given address."""
        result: set[SymbolicAddress] = set()
        for other_set in self._alias_sets.values():
            for other in other_set:
                if self.heap.may_alias(addr, other):
                    result.add(other)
        return result

    def get_must_aliases(self, addr: SymbolicAddress) -> set[SymbolicAddress]:
        """Get all addresses that must alias with the given address."""
        result: set[SymbolicAddress] = set()
        for other_set in self._alias_sets.values():
            for other in other_set:
                if self.heap.must_alias(addr, other):
                    result.add(other)
        return result

    def are_disjoint(self, addr1: SymbolicAddress, addr2: SymbolicAddress) -> bool:
        """Check if two addresses are definitely disjoint (cannot alias)."""
        return not self.heap.may_alias(addr1, addr2)


class SymbolicArray:
    """
    A symbolic array using Z3 arrays.
    Models Python lists at a symbolic level, supporting:
    - Symbolic indexing
    - Symbolic length
    - Element constraints
    """

    def __init__(self, name: str, element_sort: z3.SortRef = z3.IntSort()):
        """Init."""
        """Initialize the class instance."""
        self.name = name
        self.element_sort = element_sort
        self._array = z3.Array(f"{name}_data", z3.IntSort(), element_sort)
        self._length = z3.Int(f"{name}_len")
        self._constraints: list[z3.BoolRef] = []
        self._constraints.append(self._length >= 0)

    @property
    def length(self) -> z3.ArithRef:
        """Get the symbolic length."""
        return self._length

    @length.setter
    def length(self, value: z3.ArithRef) -> None:
        """Set the symbolic length."""
        self._length = value

    @property
    def array(self) -> z3.ArrayRef:
        """Get the underlying Z3 array."""
        return self._array

    @array.setter
    def array(self, value: z3.ArrayRef) -> None:
        """Set the underlying Z3 array."""
        self._array = value

    def get(self, index: int | z3.ArithRef) -> z3.ExprRef:
        """Get element at index (symbolic or concrete)."""
        if isinstance(index, int):
            index = z3.IntVal(index)
        return z3.Select(self._array, index)

    def set(self, index: int | z3.ArithRef, value: z3.ExprRef) -> SymbolicArray:
        """Set element at index, returning new array (functional update)."""
        if isinstance(index, int):
            index = z3.IntVal(index)
        new_array = SymbolicArray(f"{self.name}_updated", self.element_sort)
        new_array._array = z3.Store(self._array, index, value)
        new_array._length = self._length
        new_array._constraints = list(self._constraints)
        return new_array

    def append(self, value: z3.ExprRef) -> SymbolicArray:
        """Append an element, returning new array."""
        new_array = SymbolicArray(f"{self.name}_appended", self.element_sort)
        new_array._array = z3.Store(self._array, self._length, value)
        new_array._length = self._length + 1
        new_array._constraints = list(self._constraints)
        return new_array

    def get_constraints(self) -> list[z3.BoolRef]:
        """Get all constraints on this array."""
        return list(self._constraints)

    def add_constraint(self, constraint: z3.BoolRef) -> None:
        """Add a constraint on this array."""
        self._constraints.append(constraint)

    def in_bounds(self, index: int | z3.ArithRef) -> z3.BoolRef:
        """Return a constraint that index is in bounds."""
        if isinstance(index, int):
            index = z3.IntVal(index)
        return z3.And(index >= 0, index < self._length)


class SymbolicMap:
    """
    A symbolic map using Z3 arrays.
    Models Python dicts at a symbolic level, supporting:
    - Symbolic keys
    - Symbolic values
    - Key existence tracking
    """

    def __init__(
        self,
        name: str,
        key_sort: z3.SortRef = z3.IntSort(),
        value_sort: z3.SortRef = z3.IntSort(),
    ):
        """Init."""
        """Initialize the class instance."""
        self.name = name
        self.key_sort = key_sort
        self.value_sort = value_sort
        self._data = z3.Array(f"{name}_data", key_sort, value_sort)
        self._exists = z3.K(key_sort, False)
        self._constraints: list[z3.BoolRef] = []

    def get(self, key: z3.ExprRef, default: z3.ExprRef | None = None) -> z3.ExprRef:
        """Get value for key, with optional default."""
        value = z3.Select(self._data, key)
        if default is not None:
            exists = z3.Select(self._exists, key)
            return z3.If(exists, value, default)
        return value

    def set(self, key: z3.ExprRef, value: z3.ExprRef) -> SymbolicMap:
        """Set a key-value pair, returning new map."""
        new_map = SymbolicMap(f"{self.name}_updated", self.key_sort, self.value_sort)
        new_map._data = z3.Store(self._data, key, value)
        new_map._exists = z3.Store(self._exists, key, True)
        new_map._constraints = list(self._constraints)
        return new_map

    def delete(self, key: z3.ExprRef) -> SymbolicMap:
        """Delete a key, returning new map."""
        new_map = SymbolicMap(f"{self.name}_deleted", self.key_sort, self.value_sort)
        new_map._data = self._data
        new_map._exists = z3.Store(self._exists, key, False)
        new_map._constraints = list(self._constraints)
        return new_map

    def contains(self, key: z3.ExprRef) -> z3.BoolRef:
        """Check if key exists in map."""
        return cast("z3.BoolRef", z3.Select(self._exists, key))

    def get_constraints(self) -> list[z3.BoolRef]:
        """Get all constraints on this map."""
        return list(self._constraints)

    def add_constraint(self, constraint: z3.BoolRef) -> None:
        """Add a constraint on this map."""
        self._constraints.append(constraint)


__all__ = [
    "AliasingAnalyzer",
    "HeapSnapshot",
    "MemorySnapshot",
    "MemoryState",
    "SymbolicArray",
    "SymbolicHeap",
    "SymbolicMap",
]
