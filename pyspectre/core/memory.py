"""Symbolic memory model for PySpectre.
This module provides heap allocation tracking, object identity,
aliasing analysis, and pointer reasoning capabilities.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    TYPE_CHECKING,
    Any,
)
import z3

if TYPE_CHECKING:
    pass


class AllocationType(Enum):
    """Types of memory allocations."""

    OBJECT = auto()
    LIST = auto()
    DICT = auto()
    SET = auto()
    TUPLE = auto()
    STRING = auto()
    BYTES = auto()
    INSTANCE = auto()
    FUNCTION = auto()
    CLOSURE = auto()


@dataclass
class AllocationSite:
    """Represents a memory allocation site."""

    id: int
    alloc_type: AllocationType
    pc: int
    line_number: int | None = None
    size_expr: z3.ExprRef | None = None
    class_name: str | None = None

    def __hash__(self) -> int:
        return self.id

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AllocationSite):
            return False
        return self.id == other.id


@dataclass
class SymbolicPointer:
    """A symbolic pointer that can reference multiple allocation sites.
    Supports may-alias and must-alias analysis.
    """

    name: str
    possible_targets: frozenset[AllocationSite] = field(default_factory=frozenset)
    is_null: z3.BoolRef = field(default_factory=lambda: z3.Bool("null"))

    def may_alias(self, other: SymbolicPointer) -> bool:
        """Check if this pointer may alias with another."""
        return bool(self.possible_targets & other.possible_targets)

    def must_alias(self, other: SymbolicPointer) -> bool:
        """Check if this pointer must alias with another."""
        return (
            len(self.possible_targets) == 1
            and len(other.possible_targets) == 1
            and self.possible_targets == other.possible_targets
        )

    def is_definitely_null(self) -> bool:
        """Check if pointer is definitely null."""
        return len(self.possible_targets) == 0

    def is_definitely_non_null(self) -> bool:
        """Check if pointer is definitely non-null."""
        return len(self.possible_targets) > 0

    def with_target(self, target: AllocationSite) -> SymbolicPointer:
        """Create new pointer with additional possible target."""
        return SymbolicPointer(
            name=self.name,
            possible_targets=self.possible_targets | {target},
            is_null=self.is_null,
        )

    def merge(self, other: SymbolicPointer) -> SymbolicPointer:
        """Merge two pointers (for path convergence)."""
        return SymbolicPointer(
            name=f"{self.name}_merged",
            possible_targets=self.possible_targets | other.possible_targets,
            is_null=z3.Or(self.is_null, other.is_null),
        )


@dataclass
class HeapObject:
    """Represents an object on the symbolic heap."""

    allocation: AllocationSite
    fields: dict[str, Any] = field(default_factory=dict)
    array_elements: dict[z3.ExprRef, Any] = field(default_factory=dict)
    symbolic_length: z3.ExprRef | None = None
    is_mutable: bool = True

    def get_field(self, name: str) -> Any:
        """Get a field value."""
        return self.fields.get(name)

    def set_field(self, name: str, value: Any) -> None:
        """Set a field value."""
        if self.is_mutable:
            self.fields[name] = value

    def get_element(self, index: z3.ExprRef) -> Any:
        """Get an array element by symbolic index."""
        return self.array_elements.get(index)

    def set_element(self, index: z3.ExprRef, value: Any) -> None:
        """Set an array element by symbolic index."""
        if self.is_mutable:
            self.array_elements[index] = value


class SymbolicHeap:
    """Symbolic heap for tracking allocations and memory state.
    Provides:
    - Allocation tracking
    - Field reads/writes
    - Array element access
    - Aliasing analysis
    """

    def __init__(self):
        self._next_alloc_id: int = 0
        self._allocations: dict[int, AllocationSite] = {}
        self._objects: dict[int, HeapObject] = {}
        self._pointers: dict[str, SymbolicPointer] = {}
        self._alias_constraints: list[z3.BoolRef] = []

    def allocate(
        self,
        alloc_type: AllocationType,
        pc: int,
        line_number: int | None = None,
        size_expr: z3.ExprRef | None = None,
        class_name: str | None = None,
    ) -> SymbolicPointer:
        """Allocate a new object on the heap."""
        alloc_id = self._next_alloc_id
        self._next_alloc_id += 1
        site = AllocationSite(
            id=alloc_id,
            alloc_type=alloc_type,
            pc=pc,
            line_number=line_number,
            size_expr=size_expr,
            class_name=class_name,
        )
        self._allocations[alloc_id] = site
        self._objects[alloc_id] = HeapObject(allocation=site)
        ptr = SymbolicPointer(
            name=f"ptr_{alloc_id}",
            possible_targets=frozenset({site}),
            is_null=z3.BoolVal(False),
        )
        return ptr

    def get_object(self, ptr: SymbolicPointer) -> HeapObject | None:
        """Get the object pointed to by a pointer.
        Returns None if pointer may be null or points to multiple objects.
        """
        if len(ptr.possible_targets) != 1:
            return None
        target = next(iter(ptr.possible_targets))
        return self._objects.get(target.id)

    def read_field(
        self,
        ptr: SymbolicPointer,
        field_name: str,
    ) -> tuple[Any, list[z3.BoolRef]]:
        """Read a field from an object.
        Returns the value and any additional constraints.
        """
        constraints = []
        if ptr.is_definitely_null():
            return None, [z3.BoolVal(False)]
        if len(ptr.possible_targets) == 1:
            obj = self.get_object(ptr)
            if obj:
                return obj.get_field(field_name), constraints
        from pyspectre.core.types import SymbolicValue

        result = SymbolicValue(f"{ptr.name}.{field_name}")
        for target in ptr.possible_targets:
            obj = self._objects.get(target.id)
            if obj and field_name in obj.fields:
                field_val = obj.fields[field_name]
                if isinstance(field_val, SymbolicValue):
                    pass
        return result, constraints

    def write_field(
        self,
        ptr: SymbolicPointer,
        field_name: str,
        value: Any,
    ) -> list[z3.BoolRef]:
        """Write a field to an object.
        Returns any additional constraints.
        """
        constraints = []
        if ptr.is_definitely_null():
            return [z3.BoolVal(False)]
        for target in ptr.possible_targets:
            obj = self._objects.get(target.id)
            if obj and obj.is_mutable:
                obj.set_field(field_name, value)
        return constraints

    def read_array(
        self,
        ptr: SymbolicPointer,
        index: z3.ExprRef,
    ) -> tuple[Any, list[z3.BoolRef]]:
        """Read an array element."""
        constraints = []
        if ptr.is_definitely_null():
            return None, [z3.BoolVal(False)]
        obj = self.get_object(ptr)
        if obj:
            if obj.symbolic_length is not None:
                constraints.append(index >= 0)
                constraints.append(index < obj.symbolic_length)
            if index in obj.array_elements:
                return obj.array_elements[index], constraints
            from pyspectre.core.types import SymbolicValue

            elem = SymbolicValue(f"{ptr.name}[{index}]")
            obj.array_elements[index] = elem
            return elem, constraints
        from pyspectre.core.types import SymbolicValue

        return SymbolicValue(f"{ptr.name}[?]"), constraints

    def write_array(
        self,
        ptr: SymbolicPointer,
        index: z3.ExprRef,
        value: Any,
    ) -> list[z3.BoolRef]:
        """Write an array element."""
        constraints = []
        if ptr.is_definitely_null():
            return [z3.BoolVal(False)]
        obj = self.get_object(ptr)
        if obj and obj.is_mutable:
            if obj.symbolic_length is not None:
                constraints.append(index >= 0)
                constraints.append(index < obj.symbolic_length)
            obj.set_element(index, value)
        return constraints

    def may_alias(self, ptr1: SymbolicPointer, ptr2: SymbolicPointer) -> bool:
        """Check if two pointers may alias."""
        return ptr1.may_alias(ptr2)

    def must_alias(self, ptr1: SymbolicPointer, ptr2: SymbolicPointer) -> bool:
        """Check if two pointers must alias."""
        return ptr1.must_alias(ptr2)

    def get_points_to_set(self, ptr: SymbolicPointer) -> set[AllocationSite]:
        """Get the set of objects a pointer may point to."""
        return set(ptr.possible_targets)

    def copy(self) -> SymbolicHeap:
        """Create a copy of the heap for path forking."""
        new_heap = SymbolicHeap()
        new_heap._next_alloc_id = self._next_alloc_id
        new_heap._allocations = dict(self._allocations)
        new_heap._objects = {
            k: HeapObject(
                allocation=v.allocation,
                fields=dict(v.fields),
                array_elements=dict(v.array_elements),
                symbolic_length=v.symbolic_length,
                is_mutable=v.is_mutable,
            )
            for k, v in self._objects.items()
        }
        new_heap._pointers = dict(self._pointers)
        new_heap._alias_constraints = list(self._alias_constraints)
        return new_heap


class PointsToAnalysis:
    """Andersen-style points-to analysis for alias information.
    Computes which pointers may point to which allocation sites.
    """

    def __init__(self):
        self._points_to: dict[str, set[int]] = {}
        self._field_pts: dict[tuple[int, str], set[int]] = {}
        self._worklist: list[tuple[str, int]] = []

    def add_allocation(self, var: str, alloc_id: int) -> None:
        """Record that var points to alloc_id."""
        if var not in self._points_to:
            self._points_to[var] = set()
        if alloc_id not in self._points_to[var]:
            self._points_to[var].add(alloc_id)
            self._worklist.append((var, alloc_id))

    def add_assignment(self, dst: str, src: str) -> None:
        """Record assignment dst = src."""
        if src in self._points_to:
            for alloc_id in self._points_to[src]:
                self.add_allocation(dst, alloc_id)

    def add_field_load(self, dst: str, base: str, field: str) -> None:
        """Record dst = base.field."""
        if base in self._points_to:
            for obj_id in self._points_to[base]:
                key = (obj_id, field)
                if key in self._field_pts:
                    for alloc_id in self._field_pts[key]:
                        self.add_allocation(dst, alloc_id)

    def add_field_store(self, base: str, field: str, src: str) -> None:
        """Record base.field = src."""
        if base in self._points_to and src in self._points_to:
            for obj_id in self._points_to[base]:
                key = (obj_id, field)
                if key not in self._field_pts:
                    self._field_pts[key] = set()
                for alloc_id in self._points_to[src]:
                    self._field_pts[key].add(alloc_id)

    def solve(self) -> None:
        """Solve the points-to constraints."""
        changed = True
        while changed:
            changed = False
            while self._worklist:
                var, alloc_id = self._worklist.pop()

    def may_alias(self, var1: str, var2: str) -> bool:
        """Check if two variables may alias."""
        pts1 = self._points_to.get(var1, set())
        pts2 = self._points_to.get(var2, set())
        return bool(pts1 & pts2)

    def get_points_to(self, var: str) -> set[int]:
        """Get the points-to set for a variable."""
        return self._points_to.get(var, set())


class EscapeState(Enum):
    """Escape states for objects."""

    NO_ESCAPE = auto()
    ARG_ESCAPE = auto()
    GLOBAL_ESCAPE = auto()


@dataclass
class EscapeInfo:
    """Escape analysis information for an allocation."""

    allocation: AllocationSite
    state: EscapeState = EscapeState.NO_ESCAPE
    escape_points: list[int] = field(default_factory=list)

    def mark_arg_escape(self, pc: int) -> None:
        """Mark as escaping through argument."""
        if self.state == EscapeState.NO_ESCAPE:
            self.state = EscapeState.ARG_ESCAPE
        self.escape_points.append(pc)

    def mark_global_escape(self, pc: int) -> None:
        """Mark as globally escaping."""
        self.state = EscapeState.GLOBAL_ESCAPE
        self.escape_points.append(pc)


class EscapeAnalysis:
    """Determines which objects escape their allocation scope.
    Objects that don't escape can be:
    - Stack allocated
    - Eliminated if unused
    - Better optimized
    """

    def __init__(self):
        self._escape_info: dict[int, EscapeInfo] = {}

    def analyze_allocation(self, site: AllocationSite) -> EscapeInfo:
        """Get or create escape info for an allocation."""
        if site.id not in self._escape_info:
            self._escape_info[site.id] = EscapeInfo(allocation=site)
        return self._escape_info[site.id]

    def mark_return(self, ptr: SymbolicPointer, pc: int) -> None:
        """Mark pointer as returned from function."""
        for target in ptr.possible_targets:
            info = self.analyze_allocation(target)
            info.mark_global_escape(pc)

    def mark_stored_to_field(self, ptr: SymbolicPointer, pc: int) -> None:
        """Mark pointer as stored to object field."""
        for target in ptr.possible_targets:
            info = self.analyze_allocation(target)
            info.mark_global_escape(pc)

    def mark_passed_as_arg(self, ptr: SymbolicPointer, pc: int) -> None:
        """Mark pointer as passed to function."""
        for target in ptr.possible_targets:
            info = self.analyze_allocation(target)
            info.mark_arg_escape(pc)

    def get_non_escaping(self) -> list[AllocationSite]:
        """Get all allocations that don't escape."""
        return [
            info.allocation
            for info in self._escape_info.values()
            if info.state == EscapeState.NO_ESCAPE
        ]

    def can_stack_allocate(self, site: AllocationSite) -> bool:
        """Check if allocation could be stack-allocated."""
        info = self._escape_info.get(site.id)
        return info is None or info.state == EscapeState.NO_ESCAPE


__all__ = [
    "AllocationType",
    "AllocationSite",
    "SymbolicPointer",
    "HeapObject",
    "SymbolicHeap",
    "PointsToAnalysis",
    "EscapeState",
    "EscapeInfo",
    "EscapeAnalysis",
]
