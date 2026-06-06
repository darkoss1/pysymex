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

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

import z3

from pysymex.core.types.containers.helpers import known_length_truthiness, storage_int_expr
from pysymex.core.types.containers.list_sequence import SymbolicListSequenceOpsMixin
from pysymex.core.constants import Z3_FALSE
from pysymex.core.constants import Z3_INT_SORT
from pysymex.core.constants import Z3_TRUE
from pysymex.core.constants import Z3_ZERO
from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.types.base import SymbolicType
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.core.types.scalars.values import fresh_name

if TYPE_CHECKING:
    pass


@dataclass
class SymbolicList(SymbolicListSequenceOpsMixin, SymbolicType):
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

    def to_z3(self) -> z3.ExprRef:
        """Return the Z3 array expression that stores modeled list elements."""
        return self.z3_array

    def hash_value(self) -> int:
        """Return a structural hash over array and length expressions."""
        return self.z3_array.hash() ^ self.z3_len.hash()

    def could_be_truthy(self) -> z3.BoolRef:
        """Return the predicate that the represented list has positive length."""
        if self._concrete_items is not None:
            return Z3_TRUE if self._concrete_items else Z3_FALSE
        return known_length_truthiness(self.z3_len, truthy=True)

    def could_be_falsy(self) -> z3.BoolRef:
        """Return the predicate that the represented list has zero length."""
        if self._concrete_items is not None:
            return Z3_FALSE if self._concrete_items else Z3_TRUE
        return known_length_truthiness(self.z3_len, truthy=False)

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
    def symbolic_int_list(name: str | None = None) -> SymbolicList:
        """Create a symbolic integer list while discarding its length constraint."""
        list_name = name or fresh_name("list")
        symbolic_list, _ = SymbolicList.symbolic(list_name, "int")
        return symbolic_list

    @staticmethod
    def from_const(values: Sequence[object]) -> SymbolicList:
        """Create a concrete-backed symbolic list from retained items."""
        name = fresh_name("list")
        z3_array = z3.Array(f"{name}_arr", Z3_INT_SORT, Z3_INT_SORT)
        for i, v in enumerate(values):
            z3_array = z3.Store(z3_array, i, _const_item_expr(v, name))
        z3_len = get_int_val(len(values))
        lst = SymbolicList(str(values), z3_array, z3_len)
        lst._concrete_items = list(values)
        return lst

    @staticmethod
    def empty(name: str = "empty_list") -> SymbolicList:
        """Create an empty symbolic list."""
        z3_array = z3.Array(f"{name}_arr", Z3_INT_SORT, Z3_INT_SORT)
        return SymbolicList(name, z3_array, Z3_ZERO)

    @staticmethod
    def concrete_int_list(values: list[int]) -> SymbolicList:
        """Return a concrete-backed integer list via :meth:`from_const`."""
        return SymbolicList.from_const(values)

    def __getitem__(self, index: object) -> SymbolicValue:
        """Return an integer-channel element expression after negative-index normalization."""
        sym_index = index if isinstance(index, SymbolicValue) else SymbolicValue.from_const(index)
        index_expr = storage_int_expr(sym_index.z3_int, f"{self._name}_idx")
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
        )

    def element_expr_at(self, index: z3.ArithRef) -> z3.ArithRef:
        """Return the precise element expression for an observed list index."""
        if self.range_start is not None and self.range_step is not None:
            return self.range_start + index * self.range_step
        return cast("z3.ArithRef", z3.Select(self.z3_array, index))

    def __setitem__(self, index: object, value: object) -> SymbolicList:
        """Return an updated list and retain concrete items only for resolved positions."""
        sym_index = index if isinstance(index, SymbolicValue) else SymbolicValue.from_const(index)
        sym_value = value if isinstance(value, SymbolicValue) else SymbolicValue.from_const(value)
        index_expr = storage_int_expr(sym_index.z3_int, f"{self._name}_idx")
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
        )

    def __delitem__(self, index: object) -> SymbolicList:
        """Return a deletion view with later expressions shifted left."""
        sym_index = index if isinstance(index, SymbolicValue) else SymbolicValue.from_const(index)
        index_expr = storage_int_expr(sym_index.z3_int, f"{self._name}_idx")
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
        )

    def append(self, value: SymbolicValue) -> SymbolicList:
        """Return a new list with ``value`` stored at the current length."""
        new_array = z3.Store(self.z3_array, self.z3_len, self._store_expr(value))
        new_concrete = list(self._concrete_items) if self._concrete_items is not None else None
        if new_concrete is not None:
            new_concrete.append(value)
        return SymbolicList(
            _name=f"{self._name}.append({value.name})",
            z3_array=new_array,
            z3_len=self.z3_len + 1,
            element_type=self.element_type,
            _concrete_items=new_concrete,
        )

    def _store_expr(self, value: SymbolicValue) -> z3.ArithRef:
        """Return an arithmetic placeholder compatible with the list's Z3 array sort."""
        return storage_int_expr(getattr(value, "z3_int", Z3_ZERO), f"{self._name}_elem")

    def prepend(self, value: SymbolicValue) -> SymbolicList:
        """Return a new list with ``value`` at index zero."""
        idx = z3.Int(fresh_name("i"))
        new_array = cast(
            "z3.ArrayRef",
            z3.Lambda([idx], z3.If(idx == 0, value.z3_int, z3.Select(self.z3_array, idx - 1))),
        )
        new_concrete = (
            [value] + list(self._concrete_items) if self._concrete_items is not None else None
        )
        return SymbolicList(
            _name=f"{self._name}.prepend({value.name})",
            z3_array=new_array,
            z3_len=self.z3_len + 1,
            element_type=self.element_type,
            _concrete_items=new_concrete,
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

    def __repr__(self) -> str:
        """Return the diagnostic representation for this list carrier."""
        return f"SymbolicList({self._name}, len={self.z3_len})"


def _const_item_expr(value: object, list_name: str) -> z3.ArithRef:
    """Return the integer-channel storage expression for a retained concrete item."""
    if isinstance(value, SymbolicValue):
        return storage_int_expr(value.z3_int, f"{list_name}_elem")
    if isinstance(value, bool):
        return get_int_val(int(value))
    if isinstance(value, int):
        return get_int_val(value)
    return Z3_ZERO
