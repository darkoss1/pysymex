# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Container and compound symbolic types for pysymex.

Provides SymbolicList, SymbolicDict, SymbolicObject.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

import z3

from pysymex.core.types.scalars import (
    Z3_FALSE,
    Z3_TRUE,
    Z3_ZERO,
    SymbolicNone,
    SymbolicString,
    SymbolicType,
    SymbolicValue,
    fresh_name,
)

if TYPE_CHECKING:
    from pysymex.core.types.scalars import AnySymbolic


def _merge_taint_labels(
    *labels: set[str] | frozenset[str] | None,
) -> frozenset[str] | None:
    merged: set[str] = set()
    for label_group in labels:
        if label_group:
            merged.update(label_group)
    return frozenset(merged) if merged else None


@dataclass
class SymbolicList(SymbolicType):
    """Symbolic list using Z3 arrays and explicit length tracking.

    **Mathematical Model:**
    A Python list is modeled as a Z3 Array mapping integers (indices) to
    integers (symbolic values).

    **Key Constraints:**
    - `length`: A Z3 integer `len >= 0`.
    - `bounds`: Operations like `__getitem__` inject constraints `0 <= index < len`.
    - `negative indices`: Resolved via `z3.If(idx < 0, idx + len, idx)`.

    Attributes:
        _name: Debugging name
        z3_array: Z3 array from Int to symbolic elements
        z3_len: Z3 integer for list length
        element_type: String describing the element type
    """

    _name: str
    z3_array: z3.ArrayRef
    z3_len: z3.ArithRef
    element_type: str = "int"
    taint_labels: frozenset[str] | None = field(default=None, compare=False)
    _h_active: bool = field(default=False)
    _concrete_items: list[object] | None = field(default=None, compare=False)
    _type: str | None = field(default=None, compare=False)

    def __post_init__(self) -> None:
        if self._name:
            ln = self._name.lower()
            if ln in ("self", "cls") or ln.startswith(("self_", "cls_")):
                object.__setattr__(self, "_h_active", True)

    __hash__ = object.__hash__

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_array

    def hash_value(self) -> int:
        return self.z3_array.hash() ^ self.z3_len.hash()

    def could_be_truthy(self) -> z3.BoolRef:
        return self.z3_len > 0

    def could_be_falsy(self) -> z3.BoolRef:
        return self.z3_len == 0

    def with_taint(self, label: str | set[str] | frozenset[str]) -> SymbolicList:
        """Return a copy with added taint."""
        import dataclasses

        new_labels = set(self.taint_labels or set())
        if isinstance(label, str):
            new_labels.add(label)
        else:
            new_labels.update(label)
        return dataclasses.replace(self, taint_labels=frozenset(new_labels))

    def copy(self) -> SymbolicList:
        """Return a shallow copy of this symbolic list."""
        import dataclasses

        return dataclasses.replace(self)

    @staticmethod
    def symbolic(name: str, element_type: str = "int") -> tuple[SymbolicList, z3.BoolRef]:
        """Create a fresh symbolic list."""
        z3_array = z3.Array(f"{name}_arr", z3.IntSort(), z3.IntSort())
        z3_len = z3.Int(f"{name}_len")
        constraint = z3_len >= 0
        return SymbolicList(name, z3_array, z3_len, element_type), constraint

    @staticmethod
    def from_const(values: list[int]) -> SymbolicList:
        """Create a concrete symbolic list from integers."""
        name = fresh_name("list")
        z3_array = z3.Array(f"{name}_arr", z3.IntSort(), z3.IntSort())
        for i, v in enumerate(values):
            z3_array = z3.Store(z3_array, i, v)
        z3_len = z3.IntVal(len(values))
        return SymbolicList(str(values), z3_array, z3_len)

    @staticmethod
    def empty(name: str = "empty_list") -> SymbolicList:
        """Create an empty symbolic list."""
        z3_array = z3.Array(f"{name}_arr", z3.IntSort(), z3.IntSort())
        return SymbolicList(name, z3_array, z3.IntVal(0))

    def __getitem__(self, index: object) -> SymbolicValue:
        """List indexing with negative wrap-around support."""
        sym_index = index if isinstance(index, SymbolicValue) else SymbolicValue.from_const(index)
        real_idx = z3.If(sym_index.z3_int < 0, sym_index.z3_int + self.z3_len, sym_index.z3_int)
        elem = z3.Select(self.z3_array, real_idx)
        return SymbolicValue(
            _name=f"{self._name}[{sym_index.name}]",
            z3_int=cast("z3.ArithRef", elem),
            is_int=Z3_TRUE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_str=Z3_FALSE,
            is_obj=Z3_FALSE,
            is_list=Z3_FALSE,
            is_dict=Z3_FALSE,
            is_path=Z3_FALSE,
            is_none=Z3_FALSE,
            taint_labels=_merge_taint_labels(self.taint_labels, sym_index.taint_labels),
        )

    def __setitem__(self, index: object, value: object) -> SymbolicList:
        """List assignment - returns new list (immutable semantics)."""
        sym_index = index if isinstance(index, SymbolicValue) else SymbolicValue.from_const(index)
        sym_value = value if isinstance(value, SymbolicValue) else SymbolicValue.from_const(value)
        real_idx = z3.If(sym_index.z3_int < 0, sym_index.z3_int + self.z3_len, sym_index.z3_int)
        new_array = z3.Store(self.z3_array, real_idx, sym_value.z3_int)
        new_concrete = list(self._concrete_items) if self._concrete_items is not None else None
        if new_concrete is not None and z3.is_int_value(sym_index.z3_int):
            idx = sym_index.z3_int.as_long()
            if 0 <= idx < len(new_concrete):
                new_concrete[idx] = sym_value
            else:
                new_concrete = None
        else:
            new_concrete = None

        return SymbolicList(
            _name=f"{self._name}[{sym_index.name}]={sym_value.name}",
            z3_array=new_array,
            z3_len=self.z3_len,
            element_type=self.element_type,
            taint_labels=_merge_taint_labels(
                self.taint_labels,
                sym_index.taint_labels,
                sym_value.taint_labels,
            ),
            _concrete_items=new_concrete,
        )

    def append(self, value: SymbolicValue) -> SymbolicList:
        """Append element - returns new list."""
        new_array = z3.Store(self.z3_array, self.z3_len, value.z3_int)
        new_concrete = list(self._concrete_items) if self._concrete_items is not None else None
        if new_concrete is not None:
            new_concrete.append(value)
        return SymbolicList(
            _name=f"{self._name}.append({value.name})",
            z3_array=new_array,
            z3_len=self.z3_len + 1,
            element_type=self.element_type,
            taint_labels=_merge_taint_labels(self.taint_labels, value.taint_labels),
            _concrete_items=new_concrete,
        )

    def extend(self, other: SymbolicList | list[object] | tuple[object, ...]) -> SymbolicList:
        """Extend list - returns new list."""
        if isinstance(other, (list, tuple)):
            res = self
            for item in other:
                s_item = item if isinstance(item, SymbolicValue) else SymbolicValue.from_const(item)
                res = res.append(s_item)
            return res
        else:
            if other._concrete_items is not None:
                res = self
                for item in other._concrete_items:
                    s_item = (
                        item if isinstance(item, SymbolicValue) else SymbolicValue.from_const(item)
                    )
                    res = res.append(s_item)
                return res
            else:
                idx = z3.Int(fresh_name("i"))
                new_array = cast(
                    "z3.ArrayRef",
                    z3.Lambda(
                        [idx],
                        z3.If(
                            idx < self.z3_len,
                            z3.Select(self.z3_array, idx),
                            z3.Select(other.z3_array, idx - self.z3_len),
                        ),
                    ),
                )
                return SymbolicList(
                    _name=f"{self._name}.extend({other.name})",
                    z3_array=new_array,
                    z3_len=self.z3_len + other.z3_len,
                    element_type=self.element_type,
                    taint_labels=_merge_taint_labels(self.taint_labels, other.taint_labels),
                )
        return self

    def length(self) -> SymbolicValue:
        """Get list length."""
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
        """Check if index is valid (supports negative Python indices)."""
        return z3.And(index.z3_int >= -self.z3_len, index.z3_int < self.z3_len)

    def conditional_merge(
        self, other: AnySymbolic, condition: z3.BoolRef
    ) -> SymbolicList | SymbolicValue:
        """Merge with another list based on condition."""
        if not isinstance(other, SymbolicList):
            val_self = self.as_unified()
            return val_self.conditional_merge(other, condition)

        new_array = z3.If(condition, self.z3_array, other.z3_array)
        new_len = z3.If(condition, self.z3_len, other.z3_len)
        return SymbolicList(
            _name=f"If({condition}, {self._name}, {other.name})",
            z3_array=new_array,
            z3_len=new_len,
            element_type=self.element_type,
            taint_labels=_merge_taint_labels(self.taint_labels, other.taint_labels),
        )

    def __repr__(self) -> str:
        return f"SymbolicList({self._name}, len={self.z3_len})"

    def as_unified(self) -> SymbolicValue:
        """As unified."""
        from .scalars import SymbolicValue

        return SymbolicValue(
            _name=self._name,
            z3_int=self.z3_len,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_str=Z3_FALSE,
            z3_array=self.z3_array,
            is_list=Z3_TRUE,
            is_obj=Z3_FALSE,
            is_dict=Z3_FALSE,
            is_path=Z3_FALSE,
            is_none=Z3_FALSE,
            _h_active=self._h_active,
            taint_labels=self.taint_labels,
        )


@dataclass
class SymbolicDict(SymbolicType):
    """Symbolic dictionary modeling Python's mapping semantics.

    **Heap Representation:**
    Modeled as a Z3 Array mapping Z3 Strings (keys) to Z3 Integers (values).

    **Key Management:**
    Uses a `z3.SeqRef` (sequence theory) to track "known keys". This enables
    checking for key existence without requiring the solver to reason about
    arbitrarily-sized set theory.

    **Limitations:**
    Currently optimized for string keys and integer values.
    """

    _name: str
    z3_array: z3.ArrayRef
    known_keys: z3.SeqRef
    z3_len: z3.ArithRef
    taint_labels: frozenset[str] | None = field(default=None, compare=False)
    _h_active: bool = field(default=False)
    _concrete_items: dict[str, object] | None = field(default=None, compare=False)
    _has_default_factory: bool = field(default=False, compare=False)

    def __post_init__(self) -> None:
        if self._name:
            ln = self._name.lower()
            if ln in ("self", "cls") or ln.startswith(("self_", "cls_")):
                object.__setattr__(self, "_h_active", True)

    __hash__ = object.__hash__

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_array

    def copy(self) -> SymbolicDict:
        """Return a shallow copy of this symbolic dict."""
        import dataclasses

        return dataclasses.replace(self)

    def with_taint(self, label: str | set[str] | frozenset[str]) -> SymbolicDict:
        """Return a copy with added taint."""
        import dataclasses

        new_labels = set(self.taint_labels or set())
        if isinstance(label, str):
            new_labels.add(label)
        else:
            new_labels.update(label)
        return dataclasses.replace(self, taint_labels=frozenset(new_labels))

    def could_be_truthy(self) -> z3.BoolRef:
        return self.z3_len > 0

    def could_be_falsy(self) -> z3.BoolRef:
        return self.z3_len == 0

    def hash_value(self) -> int:
        """Stable hash based on Z3 array and known keys."""
        return (self.z3_array.hash() * 31) ^ (self.known_keys.hash() * 1000003) ^ self.z3_len.hash()

    @staticmethod
    def symbolic(name: str) -> tuple[SymbolicDict, z3.BoolRef]:
        """Create a fresh symbolic dict."""
        z3_array = z3.Array(f"{name}_dict", z3.StringSort(), z3.IntSort())
        known_keys = z3.Empty(z3.SeqSort(z3.StringSort()))
        z3_len = z3.Int(f"{name}_len")
        constraint = z3_len >= 0
        return SymbolicDict(name, z3_array, known_keys, z3_len), constraint

    @staticmethod
    def empty(name: str = "empty_dict") -> SymbolicDict:
        """Create an empty symbolic dict."""
        z3_array = z3.Array(f"{name}_dict", z3.StringSort(), z3.IntSort())
        known_keys = z3.Empty(z3.SeqSort(z3.StringSort()))
        z3_len = z3.IntVal(0)
        return SymbolicDict(name, z3_array, known_keys, z3_len)

    @staticmethod
    def from_const(values: dict[str, object]) -> SymbolicDict:
        """Create a symbolic dict initialized from a concrete mapping."""
        result = SymbolicDict.empty(name=fresh_name("const_dict"))
        for key, value in values.items():
            result = result.__setitem__(key, value)
        return result

    def __getitem__(self, key: object) -> tuple[SymbolicValue, z3.BoolRef]:
        """Dict lookup. Returns (value, presence_check)."""
        sym_key = key if isinstance(key, SymbolicString) else SymbolicString.from_const(str(key))
        elem = z3.Select(self.z3_array, sym_key.z3_str)

        presence_check = z3.Contains(self.known_keys, z3.Unit(sym_key.z3_str))
        val = SymbolicValue(
            _name=f"{self._name}[{sym_key.name}]",
            z3_int=cast("z3.ArithRef", elem),
            is_int=Z3_TRUE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_str=Z3_FALSE,
            is_obj=Z3_FALSE,
            is_list=Z3_FALSE,
            is_dict=Z3_FALSE,
            is_path=Z3_FALSE,
            is_none=Z3_FALSE,
            taint_labels=_merge_taint_labels(self.taint_labels, sym_key.taint_labels),
        )
        return val, presence_check

    def __setitem__(self, key: object, value: object) -> SymbolicDict:
        """Dict assignment - returns new dict. Prevents redundant key growth."""
        sym_key = key if isinstance(key, SymbolicString) else SymbolicString.from_const(str(key))
        sym_value = value if isinstance(value, SymbolicValue) else SymbolicValue.from_const(value)
        new_array = z3.Store(self.z3_array, sym_key.z3_str, sym_value.z3_int)
        key_unit = z3.Unit(sym_key.z3_str)
        is_existing_key = z3.Contains(self.known_keys, key_unit)
        new_keys = z3.If(
            is_existing_key,
            self.known_keys,
            z3.Concat(self.known_keys, key_unit),
        )
        new_len = z3.If(is_existing_key, self.z3_len, self.z3_len + 1)
        new_concrete = dict(self._concrete_items) if self._concrete_items is not None else None
        if new_concrete is not None and z3.is_string_value(sym_key.z3_str):
            new_concrete[sym_key.z3_str.as_string()] = sym_value
        else:
            new_concrete = None

        return SymbolicDict(
            _name=f"{self._name}[{sym_key.name}]={sym_value.name}",
            z3_array=new_array,
            known_keys=new_keys,
            z3_len=new_len,
            taint_labels=_merge_taint_labels(
                self.taint_labels,
                sym_key.taint_labels,
                sym_value.taint_labels,
            ),
            _concrete_items=new_concrete,
        )

    def update(self, other: SymbolicDict | dict[str, object]) -> tuple[SymbolicDict, z3.BoolRef]:
        """Update dict - returns (new_dict, constraint)."""
        if isinstance(other, dict):
            res = self
            all_constraints = []
            for k, v in other.items():
                res = res.__setitem__(k, v)
            return res, z3.And(*all_constraints) if all_constraints else z3.BoolVal(True)
        else:
            if other._concrete_items is not None:
                res = self
                for k, v in other._concrete_items.items():
                    res = res.__setitem__(k, v)
                return res, z3.BoolVal(True)
            else:
                k = z3.String(fresh_name("k"))

                other_has_k = z3.Contains(other.known_keys, z3.Unit(k))
                new_array = cast(
                    "z3.ArrayRef",
                    z3.Lambda(
                        [k],
                        z3.If(
                            other_has_k,
                            z3.Select(other.z3_array, k),
                            z3.Select(self.z3_array, k),
                        ),
                    ),
                )
                new_keys = z3.Concat(self.known_keys, other.known_keys)

                new_len = z3.Int(fresh_name("updated_len"))

                max_len = z3.If(self.z3_len > other.z3_len, self.z3_len, other.z3_len)
                sum_len = self.z3_len + other.z3_len

                constraint = z3.And(new_len >= max_len, new_len <= sum_len)

                return SymbolicDict(
                    _name=f"{self._name}.update({other.name})",
                    z3_array=new_array,
                    known_keys=new_keys,
                    z3_len=new_len,
                    taint_labels=_merge_taint_labels(self.taint_labels, other.taint_labels),
                ), constraint
        return self, z3.BoolVal(True)

    def contains_key(self, key: SymbolicString) -> SymbolicValue:
        """Check if key exists."""
        result = z3.Contains(self.known_keys, z3.Unit(key.z3_str))
        return SymbolicValue(
            _name=f"({key.name} in {self._name})",
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=result,
            is_bool=Z3_TRUE,
            is_str=Z3_FALSE,
            is_obj=Z3_FALSE,
            is_list=Z3_FALSE,
            is_dict=Z3_FALSE,
            is_path=Z3_FALSE,
            is_none=Z3_FALSE,
            taint_labels=_merge_taint_labels(self.taint_labels, key.taint_labels),
        )

    def __contains__(self, key: object) -> bool:
        """Dict membership check (concrete). Returns False for symbolic keys to avoid iteration."""
        return False

    def conditional_merge(
        self, other: AnySymbolic, condition: z3.BoolRef
    ) -> SymbolicDict | SymbolicValue:
        """Merge with another dict based on condition."""
        if not isinstance(other, SymbolicDict):
            val_self = self.as_unified()
            return val_self.conditional_merge(other, condition)

        new_array = z3.If(condition, self.z3_array, other.z3_array)
        new_keys = z3.If(condition, self.known_keys, other.known_keys)
        new_len = z3.If(condition, self.z3_len, other.z3_len)
        return SymbolicDict(
            _name=f"If({condition}, {self._name}, {other.name})",
            z3_array=new_array,
            known_keys=new_keys,
            z3_len=new_len,
            taint_labels=_merge_taint_labels(self.taint_labels, other.taint_labels),
        )

    def __repr__(self) -> str:
        return f"SymbolicDict({self._name})"

    def as_unified(self) -> SymbolicValue:
        """As unified."""
        from .scalars import SymbolicValue

        return SymbolicValue(
            _name=self._name,
            z3_int=self.z3_len,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_str=Z3_FALSE,
            z3_array=self.z3_array,
            is_dict=Z3_TRUE,
            is_list=Z3_FALSE,
            is_obj=Z3_FALSE,
            is_none=Z3_FALSE,
            is_path=Z3_FALSE,
            _h_active=self._h_active,
            taint_labels=self.taint_labels,
        )


@dataclass
class SymbolicObject(SymbolicType):
    """Symbolic object references (with heap address).
    Attributes:
        _name: Debugging name
        address: Heap address (integer)
        z3_addr: Z3 integer representing the address
    """

    _name: str
    address: int
    z3_addr: z3.ArithRef
    potential_addresses: set[int] = field(default_factory=lambda: set())
    _h_active: bool = field(default=False)

    __hash__ = object.__hash__

    def __post_init__(self) -> None:
        """Post init."""
        if not self.potential_addresses and self.address != -1:
            self.potential_addresses = {self.address}
        if self._name:
            ln = self._name.lower()
            if ln in ("self", "cls") or ln.startswith(("self_", "cls_")):
                object.__setattr__(self, "_h_active", True)

    @property
    def name(self) -> str:
        return self._name

    @property
    def is_int(self) -> z3.BoolRef:
        """Property returning the is_int."""
        return Z3_FALSE

    @property
    def is_bool(self) -> z3.BoolRef:
        """Property returning the is_bool."""
        return Z3_FALSE

    @property
    def is_str(self) -> z3.BoolRef:
        """Property returning the is_str."""
        return Z3_FALSE

    @property
    def is_none(self) -> z3.BoolRef:
        """Property returning the is_none."""
        return Z3_FALSE

    @property
    def is_obj(self) -> z3.BoolRef:
        """Property returning the is_obj."""
        return Z3_TRUE

    @property
    def is_path(self) -> z3.BoolRef:
        """Property returning the is_path."""
        return Z3_FALSE

    def to_z3(self) -> z3.ExprRef:
        return self.z3_addr

    def could_be_truthy(self) -> z3.BoolRef:
        return self.z3_addr != 0

    def could_be_falsy(self) -> z3.BoolRef:
        return self.z3_addr == 0

    @staticmethod
    def symbolic(name: str, address: int) -> tuple[SymbolicObject, z3.BoolRef]:
        """Create a fresh symbolic object."""
        if address >= 0:
            z3_addr = z3.IntVal(address)
            constraint = Z3_TRUE
        else:
            z3_addr = z3.Int(f"{name}_addr")
            constraint = Z3_TRUE
        return SymbolicObject(name, address, z3_addr, {address}), constraint

    @staticmethod
    def from_const(value: object) -> SymbolicObject:
        """Create from existing object (requires address management - usually caller handles this)."""
        addr = id(value)
        return SymbolicObject(f"obj_{addr}", addr, z3.IntVal(addr), {addr})

    def __eq__(self, other: object) -> SymbolicValue:  # type: ignore[override]
        """Symbolic identity equality (models Python object identity checks)."""
        if isinstance(other, SymbolicObject):
            cond = self.z3_addr == other.z3_addr
            other_name = other.name
        elif isinstance(other, SymbolicNone):
            cond = self.z3_addr == 0
            other_name = "None"
        else:
            cond = Z3_FALSE
            other_name = str(type(other).__name__)

        return SymbolicValue(
            _name=f"({self._name}=={other_name})",
            z3_int=z3.If(cond, z3.IntVal(1), Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=cond,
            is_bool=Z3_TRUE,
            is_str=Z3_FALSE,
            is_obj=Z3_FALSE,
            is_list=Z3_FALSE,
            is_dict=Z3_FALSE,
            is_path=Z3_FALSE,
            is_none=Z3_FALSE,
        )

    def __ne__(self, other: object) -> SymbolicValue:  # type: ignore[override]
        """Symbolic identity inequality."""
        eq_result = self.__eq__(other)
        neq_cond = z3.Not(eq_result.z3_bool)
        return SymbolicValue(
            _name=f"({self._name}!={getattr(other, 'name', str(type(other).__name__))})",
            z3_int=z3.If(neq_cond, z3.IntVal(1), Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=neq_cond,
            is_bool=Z3_TRUE,
            is_str=Z3_FALSE,
            is_obj=Z3_FALSE,
            is_list=Z3_FALSE,
            is_dict=Z3_FALSE,
            is_path=Z3_FALSE,
            is_none=Z3_FALSE,
        )

    def __repr__(self) -> str:
        return f"SymbolicObject({self._name}, addr={self.address})"

    def conditional_merge(
        self, other: AnySymbolic, condition: z3.BoolRef
    ) -> SymbolicObject | SymbolicValue:
        """Merge with another object."""
        if isinstance(other, SymbolicNone):
            new_addr = z3.If(condition, self.z3_addr, z3.IntVal(0))
            return SymbolicObject(
                _name=f"If({condition}, {self._name}, None)",
                address=-1,
                z3_addr=new_addr,
                potential_addresses=self.potential_addresses.copy(),
            )
        if isinstance(other, SymbolicObject):
            new_addr = z3.If(condition, self.z3_addr, other.z3_addr)
            return SymbolicObject(
                _name=f"If({condition}, {self._name}, {other.name})",
                address=-1 if self.address != other.address else self.address,
                z3_addr=new_addr,
                potential_addresses=self.potential_addresses.union(other.potential_addresses),
            )
        val_self = self.as_unified()
        return val_self.conditional_merge(other, condition)

    def as_unified(self) -> SymbolicValue:
        """As unified."""
        from .scalars import SymbolicValue

        return SymbolicValue(
            _name=self._name,
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_str=Z3_FALSE,
            z3_addr=self.z3_addr,
            is_obj=Z3_TRUE,
            is_list=Z3_FALSE,
            is_dict=Z3_FALSE,
            is_none=Z3_FALSE,
            is_path=Z3_FALSE,
            _h_active=self._h_active,
            taint_labels=None,
        )

    def hash_value(self) -> int:
        """Stable hash based on address."""
        h = hash(self.address)
        h = (h * 31) ^ self.z3_addr.hash()
        if self.potential_addresses:
            h = (h * 31) ^ hash(frozenset(self.potential_addresses))
        return h


@dataclass(slots=True)
class SymbolicIterator(SymbolicType):
    """Symbolic iterator tracking the source sequence."""

    _name: str
    iterable: object
    index: int = 0

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return z3.IntVal(0)

    def hash_value(self) -> int:
        return hash(("iterator", id(self.iterable), self.index))

    def could_be_truthy(self) -> z3.BoolRef:
        return z3.BoolVal(True)

    def could_be_falsy(self) -> z3.BoolRef:
        return z3.BoolVal(False)

    def __repr__(self) -> str:
        return f"SymbolicIterator(of {self.iterable}, index={self.index})"

    def advance(self) -> SymbolicIterator:
        """Return a new iterator with incremented index."""
        import dataclasses

        return dataclasses.replace(self, index=self.index + 1)

    def as_unified(self) -> SymbolicValue:
        """As unified representation."""
        from .scalars import SymbolicValue

        return SymbolicValue(
            _name=self._name,
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_path=Z3_FALSE,
        )
