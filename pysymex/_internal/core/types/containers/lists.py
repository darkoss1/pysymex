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

"""Int-valued symbolic list storage with optional retained concrete elements."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_INT_SORT, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.base import SymbolicType, fresh_name
from pysymex._internal.core.types.containers.list.items import const_item_expr
from pysymex._internal.core.types.containers.list.sequence import ListSequenceOpsMixin
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.containers.storage_ops import ContainerStorageOps
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from collections.abc import Sequence

    from pysymex._internal.core.state.record import VMState


@dataclass
class SymbolicList(ListSequenceOpsMixin, SymbolicType):
    """Symbolic list represented by an Int-indexed Z3 array and length.

    Index operations normalize negative indices with an ``If`` expression.
    Bounds checking is available through :meth:`in_bounds`; element access
    itself does not add a bounds constraint.

    Attributes:
        _name: Debugging name.
        z3_array: Z3 array from integer indices to integer payloads.
        z3_len: Expression representing the list length.
        element_type: Label for the represented element type.
        range_start: Start expression when this list models ``range``.
        range_step: Step expression when this list models ``range``.

    Limitations:
        Storage preserves integer payload channels; concrete-element metadata
        is retained only while mutations use resolvable concrete positions.

    """

    _name: str
    z3_array: z3.ArrayRef
    z3_len: z3.ArithRef
    element_type: str = "int"
    _h_active: bool = field(default=False)
    _concrete_items: list[object] | None = field(default=None, compare=False)
    _type: str | None = field(default=None, compare=False)
    _derived_sequence_kind: str | None = field(default=None, compare=False, repr=False)
    _derived_source_str: z3.SeqRef | None = field(default=None, compare=False, repr=False)
    range_start: z3.ArithRef | None = field(default=None, compare=False, repr=False)
    range_step: z3.ArithRef | None = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        """Mark receiver-like list names for heuristic tracking."""
        if self._name:
            ln = self._name.lower()
            if ln in ("self", "cls") or ln.startswith(("self_", "cls_")):
                self._h_active = True

    __hash__ = object.__hash__

    @property
    def name(self) -> str:
        """Return the diagnostic name for this symbolic list."""
        return self._name

    @property
    def concrete_items(self) -> list[object] | None:
        """Return concrete elements when the list was materialized from constants."""
        return self._concrete_items

    @property
    def is_list(self) -> z3.BoolRef:
        """Return the definite list-type marker for this carrier."""
        return Z3_TRUE

    def set_runtime_type(self, type_name: str) -> None:
        """Set the runtime type label for list-like carriers."""
        self._type = type_name

    def set_derived_sequence(self, kind: str, source_str: z3.SeqRef) -> None:
        """Attach provenance for sequence payloads derived from another scalar."""
        self._derived_sequence_kind = kind
        self._derived_source_str = source_str

    def set_concrete_items(self, items: Sequence[object]) -> None:
        """Replace retained concrete list items."""
        self._concrete_items = list(items)

    @property
    def runtime_type(self) -> str | None:
        """Return the runtime type label for list-like carriers."""
        return self._type

    def to_z3(self) -> z3.ExprRef:
        """Return the Z3 array expression that stores modeled list elements."""
        return self.z3_array

    def hash_value(self) -> int:
        """Return a structural hash over array and length expressions."""
        return self.z3_array.hash() ^ self.z3_len.hash()

    def symbolic_length(self) -> z3.ArithRef:
        """Return the represented list length."""
        return self.z3_len

    def could_be_truthy(self) -> z3.BoolRef:
        """Return the predicate that the represented list has positive length."""
        if self._concrete_items is not None:
            return Z3_TRUE if self._concrete_items else Z3_FALSE
        return ContainerStorageOps.known_length_truthiness(self.z3_len, truthy=True)

    def could_be_falsy(self) -> z3.BoolRef:
        """Return the predicate that the represented list has zero length."""
        if self._concrete_items is not None:
            return Z3_FALSE if self._concrete_items else Z3_TRUE
        return ContainerStorageOps.known_length_truthiness(self.z3_len, truthy=False)

    def len_is_definitely_zero(self) -> bool:
        """Return whether the solver can prove this list has zero length."""
        return z3.is_true(simplify_expr(self.z3_len == 0))

    def copy(self) -> SymbolicList:
        """Return a shallow copy of this symbolic list."""
        import dataclasses

        copied = dataclasses.replace(self)
        if self._concrete_items is not None:
            copied._concrete_items = list(self._concrete_items)
        return copied

    @staticmethod
    def symbolic(name: str, element_type: str = "int") -> tuple[SymbolicList, z3.BoolRef]:
        """Create a symbolic list and its nonnegative-length constraint."""
        z3_array = z3.Array(f"{name}_arr", Z3_INT_SORT, Z3_INT_SORT)
        z3_len = z3.Int(f"{name}_len")
        constraint = z3_len >= 0
        return SymbolicList(name, z3_array, z3_len, element_type), constraint

    @staticmethod
    def from_const(values: Sequence[object]) -> SymbolicList:
        """Create a concrete-backed symbolic list from retained items."""
        name = fresh_name("list")
        z3_array = z3.Array(f"{name}_arr", Z3_INT_SORT, Z3_INT_SORT)
        for i, v in enumerate(values):
            z3_array = z3.Store(z3_array, i, const_item_expr(v, name))
        z3_len = ConstraintValues.int(len(values))
        lst = SymbolicList(str(values), z3_array, z3_len)
        lst._concrete_items = list(values)
        return lst

    @staticmethod
    def empty(name: str = "empty_list") -> SymbolicList:
        """Create an empty symbolic list."""
        z3_array = z3.Array(f"{name}_arr", Z3_INT_SORT, Z3_INT_SORT)
        return SymbolicList(name, z3_array, Z3_ZERO)

    def __getitem__(self, index: object) -> SymbolicValue:
        """Return an integer-channel element expression after negative-index normalization."""
        sym_index = index if isinstance(index, SymbolicValue) else SymbolicValue.from_const(index)
        index_expr = ContainerStorageOps.storage_int_expr(sym_index.z3_int, f"{self._name}_idx")
        real_idx = z3.If(index_expr < 0, index_expr + self.z3_len, index_expr)
        elem = self.element_expr_at(real_idx)
        return SymbolicValue(
            _name=f"{self._name}[{sym_index.name}]",
            z3_int=elem,
            is_int=Z3_TRUE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_str=Z3_FALSE,
            is_obj=Z3_FALSE,
            is_list=Z3_FALSE,
            is_dict=Z3_FALSE,
            is_path=Z3_FALSE,
            is_none=Z3_FALSE,
            affinity_type=self.element_type,
        )

    def element_expr_at(self, index: z3.ArithRef) -> z3.ArithRef:
        """Return the precise element expression for an observed list index."""
        if self.range_start is not None and self.range_step is not None:
            return self.range_start + index * self.range_step
        return cast("z3.ArithRef", z3.Select(self.z3_array, index))

    def __setitem__(self, index: object, value: object) -> SymbolicList:
        """Return an updated list and retain concrete items only for resolved positions."""
        sym_index = index if isinstance(index, SymbolicValue) else SymbolicValue.from_const(index)
        sym_value = value if isinstance(value, SymbolicType) else SymbolicValue.from_const(value)
        index_expr = ContainerStorageOps.storage_int_expr(sym_index.z3_int, f"{self._name}_idx")
        real_idx = z3.If(index_expr < 0, index_expr + self.z3_len, index_expr)
        new_array = z3.Store(self.z3_array, real_idx, self._store_expr(sym_value))
        new_concrete = list(self._concrete_items) if self._concrete_items is not None else None
        if new_concrete is not None and z3.is_int_value(sym_index.z3_int):
            idx = sym_index.z3_int.as_long()
            if -len(new_concrete) <= idx < len(new_concrete):
                new_concrete[idx % len(new_concrete)] = sym_value
            else:
                new_concrete = None
        else:
            new_concrete = None

        return SymbolicList(
            _name=f"{self._name}[{sym_index.name}]={sym_value.name}",
            z3_array=new_array,
            z3_len=self.z3_len,
            element_type=self.element_type,
            _concrete_items=new_concrete,
            _type=self._type,
        )

    def __delitem__(self, index: object) -> SymbolicList:
        """Return a deletion view with later expressions shifted left."""
        sym_index = index if isinstance(index, SymbolicValue) else SymbolicValue.from_const(index)
        index_expr = ContainerStorageOps.storage_int_expr(sym_index.z3_int, f"{self._name}_idx")
        real_idx = z3.If(index_expr < 0, index_expr + self.z3_len, index_expr)
        item_idx = z3.Int(fresh_name(f"{self._name}_del_idx"))
        new_array = cast(
            "z3.ArrayRef",
            z3.Lambda(
                [item_idx],
                z3.If(
                    item_idx < real_idx,
                    z3.Select(self.z3_array, item_idx),
                    z3.Select(self.z3_array, item_idx + 1),
                ),
            ),
        )
        new_concrete = list(self._concrete_items) if self._concrete_items is not None else None
        if new_concrete is not None and z3.is_int_value(sym_index.z3_int):
            idx = sym_index.z3_int.as_long()
            if -len(new_concrete) <= idx < len(new_concrete):
                del new_concrete[idx]
            else:
                new_concrete = None
        else:
            new_concrete = None

        return SymbolicList(
            _name=f"del {self._name}[{sym_index.name}]",
            z3_array=new_array,
            z3_len=self.z3_len - 1,
            element_type=self.element_type,
            _concrete_items=new_concrete,
            _type=self._type,
        )

    def append(self, value: object) -> SymbolicList:
        """Return a new list with ``value`` stored at the current length."""
        sym_value = value if isinstance(value, SymbolicType) else SymbolicValue.from_const(value)
        new_array = z3.Store(self.z3_array, self.z3_len, self._store_expr(sym_value))
        new_concrete = list(self._concrete_items) if self._concrete_items is not None else None
        if new_concrete is not None:
            new_concrete.append(sym_value)
        return SymbolicList(
            _name=f"{self._name}.append({_item_name(sym_value)})",
            z3_array=new_array,
            z3_len=self.z3_len + 1,
            element_type=self.element_type,
            _concrete_items=new_concrete,
            _type=self._type,
        )

    def _store_expr(self, value: object) -> z3.ArithRef:
        """Return an arithmetic placeholder compatible with the list's Z3 array sort."""
        from pysymex._internal.core.types.containers.objects import SymbolicObject

        if not isinstance(value, (SymbolicObject, SymbolicValue)):
            if not hasattr(value, "z3_addr") and not hasattr(value, "z3_int"):
                value = SymbolicValue.from_const(value)

        if isinstance(value, SymbolicObject):
            return ContainerStorageOps.storage_int_expr(value.z3_addr, f"{self._name}_elem")
        if isinstance(value, SymbolicValue):
            if z3.is_false(value.is_obj):
                return ContainerStorageOps.storage_int_expr(value.z3_int, f"{self._name}_elem")
            if z3.is_true(value.is_obj):
                return ContainerStorageOps.storage_int_expr(value.z3_addr, f"{self._name}_elem")
            expr = z3.If(value.is_obj, value.z3_addr, value.z3_int)
            return ContainerStorageOps.storage_int_expr(expr, f"{self._name}_elem")
        address_expr = getattr(value, "z3_addr", None)
        if isinstance(address_expr, z3.ArithRef) and not isinstance(value, SymbolicValue):
            return ContainerStorageOps.storage_int_expr(address_expr, f"{self._name}_elem")
        return ContainerStorageOps.storage_int_expr(
            getattr(value, "z3_int", Z3_ZERO),
            f"{self._name}_elem",
        )

    def prepend(self, value: SymbolicValue) -> SymbolicList:
        """Return a new list with ``value`` at index zero."""
        idx = z3.Int(fresh_name("i"))
        new_array = cast(
            "z3.ArrayRef",
            z3.Lambda([idx], z3.If(idx == 0, value.z3_int, z3.Select(self.z3_array, idx - 1))),
        )
        new_concrete = (
            [value, *list(self._concrete_items)] if self._concrete_items is not None else None
        )
        return SymbolicList(
            _name=f"{self._name}.prepend({value.name})",
            z3_array=new_array,
            z3_len=self.z3_len + 1,
            element_type=self.element_type,
            _concrete_items=new_concrete,
            _type=self._type,
        )

    def length(self) -> SymbolicValue:
        """Return the list length as an integer-channel ``SymbolicValue``."""
        return SymbolicValue(
            _name=f"len({self._name})",
            z3_int=self.z3_len,
            is_int=Z3_TRUE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_str=Z3_FALSE,
            is_obj=Z3_FALSE,
            is_list=Z3_FALSE,
            is_dict=Z3_FALSE,
            is_path=Z3_FALSE,
            is_none=Z3_FALSE,
        )

    def in_bounds(self, index: SymbolicValue) -> z3.BoolRef:
        """Return the Python-style valid-index predicate for this list."""
        return z3.And(index.z3_int >= -self.z3_len, index.z3_int < self.z3_len)

    @staticmethod
    def resolve(arg: object, state: VMState) -> SymbolicList | None:
        """Return a list carrier directly or through a heap object handle."""
        if isinstance(arg, SymbolicList):
            return arg
        if isinstance(arg, SymbolicObject):
            value = state.memory.get(arg.address)
            if isinstance(value, SymbolicList):
                return value
        return None

    @staticmethod
    def resolve_bytes(arg: object, state: VMState | None = None) -> SymbolicList | None:
        """Return bytes/bytearray list storage when the carrier is tagged as bytes-like."""
        if isinstance(arg, SymbolicList):
            return arg
        if state is not None and isinstance(arg, SymbolicObject):
            if arg.address in state.memory:
                value = state.memory[arg.address]
                if isinstance(value, SymbolicList) and getattr(value, "_type", None) in {
                    "bytes",
                    "bytearray",
                }:
                    return value
        symbolic_list = getattr(arg, "_symbolic_list", None)
        return symbolic_list if isinstance(symbolic_list, SymbolicList) else None

    @staticmethod
    def concrete_bytes_literal(arg: object) -> bytes | None:
        """Return concrete bytes when a bytes-like symbolic list is exact."""
        if isinstance(arg, bytes):
            return arg
        if isinstance(arg, bytearray):
            return bytes(arg)
        if isinstance(arg, memoryview):
            return arg.tobytes()
        if isinstance(arg, SymbolicValue):
            value = arg.value
            if isinstance(value, bytes):
                return value
            if isinstance(value, bytearray):
                return bytes(value)
            if isinstance(value, memoryview):
                return value.tobytes()
        carrier = SymbolicList.resolve_bytes(arg)
        if carrier is None:
            return None
        items = carrier.concrete_items
        if items is None:
            return None
        byte_values: list[int] = []
        for item in items:
            if not isinstance(item, int) or not 0 <= item <= 255:
                return None
            byte_values.append(item)
        return bytes(byte_values)

    def __repr__(self) -> str:
        """Return the diagnostic representation for this list carrier."""
        return f"SymbolicList({self._name}, len={self.z3_len})"


def _item_name(value: object) -> str:
    """Return a bounded diagnostic name for a retained list item."""
    name = getattr(value, "name", None)
    if isinstance(name, str):
        return name
    return type(value).__name__
