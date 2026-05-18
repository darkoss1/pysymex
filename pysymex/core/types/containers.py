# pysymex: Python Symbolic Execution & Formal Verification
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

"""Container and compound symbolic types for pysymex.

Provides SymbolicList, SymbolicDict, SymbolicObject.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

import z3

from pysymex.core.types.numeric import SymbolicBool, SymbolicInt
from pysymex.core.types.base import safe_z3_eq
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
    from pysymex.core.types import AnySymbolic


def storage_int_expr(expr: object, name_prefix: str) -> z3.ArithRef:
    """Return an Int expression suitable for Int-backed collection arrays."""
    if isinstance(expr, z3.ArithRef) and z3.is_int(expr):
        return expr
    return z3.Int(fresh_name(name_prefix))


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
    _h_active: bool = field(default=False)
    _concrete_items: list[object] | None = field(default=None, compare=False)
    _type: str | None = field(default=None, compare=False)

    def __post_init__(self) -> None:
        if self._name:
            ln = self._name.lower()
            if ln in ("self", "cls") or ln.startswith(("self_", "cls_")):
                self._h_active = True

    __hash__ = object.__hash__

    @property
    def name(self) -> str:
        return self._name

    @property
    def concrete_items(self) -> list[object] | None:
        """Return concrete elements when the list was materialized from constants."""
        return self._concrete_items

    @property
    def is_list(self) -> z3.BoolRef:
        return Z3_TRUE

    def to_z3(self) -> z3.ExprRef:
        return self.z3_array

    def hash_value(self) -> int:
        return self.z3_array.hash() ^ self.z3_len.hash()

    def could_be_truthy(self) -> z3.BoolRef:
        return self.z3_len > 0

    def could_be_falsy(self) -> z3.BoolRef:
        return self.z3_len == 0

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
    def symbolic_int_list(name: str | None = None) -> SymbolicList:
        """Compatibility constructor used by newer call sites."""
        list_name = name or fresh_name("list")
        symbolic_list, _ = SymbolicList.symbolic(list_name, "int")
        return symbolic_list

    @staticmethod
    def from_const(values: list[int]) -> SymbolicList:
        """Create a concrete symbolic list from integers."""
        name = fresh_name("list")
        z3_array = z3.Array(f"{name}_arr", z3.IntSort(), z3.IntSort())
        for i, v in enumerate(values):
            z3_array = z3.Store(
                z3_array,
                i,
                getattr(v, "z3_int", z3.IntVal(v)) if hasattr(v, "z3_int") else z3.IntVal(v),
            )
        z3_len = z3.IntVal(len(values))
        lst = SymbolicList(str(values), z3_array, z3_len)
        lst._concrete_items = list(values)
        return lst

    @staticmethod
    def empty(name: str = "empty_list") -> SymbolicList:
        """Create an empty symbolic list."""
        z3_array = z3.Array(f"{name}_arr", z3.IntSort(), z3.IntSort())
        return SymbolicList(name, z3_array, z3.IntVal(0))

    @staticmethod
    def concrete_int_list(values: list[int]) -> SymbolicList:
        """Compatibility constructor used by newer call sites."""
        return SymbolicList.from_const(values)

    def __getitem__(self, index: object) -> SymbolicValue:
        """List indexing with negative wrap-around support."""
        sym_index = index if isinstance(index, SymbolicValue) else SymbolicValue.from_const(index)
        index_expr = storage_int_expr(sym_index.z3_int, f"{self._name}_idx")
        real_idx = z3.If(index_expr < 0, index_expr + self.z3_len, index_expr)
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
        )

    def __setitem__(self, index: object, value: object) -> SymbolicList:
        """List assignment - returns new list (immutable semantics)."""
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
        """List item deletion - returns new list with later elements shifted left."""
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
        """Append element - returns new list."""
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
        """Prepend element - returns new list."""
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

    def rotate(self, n: int | z3.ArithRef) -> SymbolicList:
        """Rotate list n steps to the right - returns new list."""
        if isinstance(n, int) and n == 0:
            return self

        idx = z3.Int(fresh_name("i"))

        safe_len = z3.If(self.z3_len == 0, z3.IntVal(1), self.z3_len)
        shift = n if isinstance(n, z3.ArithRef) else z3.IntVal(n)

        from pysymex.core.types.scalars import py_mod

        real_idx = py_mod(idx - shift, safe_len)

        new_array = cast("z3.ArrayRef", z3.Lambda([idx], z3.Select(self.z3_array, real_idx)))

        new_concrete = None
        if self._concrete_items is not None and isinstance(n, int):
            import collections

            d = collections.deque(self._concrete_items)
            d.rotate(n)
            new_concrete = list(d)

        return SymbolicList(
            _name=f"{self._name}.rotate({n})",
            z3_array=new_array,
            z3_len=self.z3_len,
            element_type=self.element_type,
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
                )

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
        """Merge with another list based on condition.

        Optimized to only create z3.If() for fields that actually differ,
        reducing AST bloat.
        """
        if not isinstance(other, SymbolicList):
            val_self = SymbolicValue.from_specialized(self)
            return val_self.conditional_merge(other, condition)

        if self is other:
            return self

        are_arrays_equal = self.z3_array is other.z3_array or safe_z3_eq(
            self.z3_array, other.z3_array
        )
        new_array = (
            self.z3_array if are_arrays_equal else z3.If(condition, self.z3_array, other.z3_array)
        )

        are_lens_equal = self.z3_len is other.z3_len or safe_z3_eq(self.z3_len, other.z3_len)
        new_len = self.z3_len if are_lens_equal else z3.If(condition, self.z3_len, other.z3_len)

        return SymbolicList(
            _name=f"If({condition}, {self._name}, {other.name})",
            z3_array=new_array,
            z3_len=new_len,
            element_type=self.element_type,
        )

    def __repr__(self) -> str:
        return f"SymbolicList({self._name}, len={self.z3_len})"


@dataclass
class SymbolicDict(SymbolicType):
    """Symbolic dictionary modeling Python's mapping semantics.

    **Heap Representation:**
    Modeled as a Z3 Array mapping Z3 Strings (keys) to Z3 Integers (values).

    **Key Management:**
    Uses a `z3.ArrayRef` as a set (String -> Bool) to track "known keys".
    This enables efficient checking for key existence and supports deletion.

    **Limitations:**
    Currently optimized for string keys and integer values.
    """

    _name: str
    z3_array: z3.ArrayRef
    known_keys: z3.ArrayRef
    z3_len: z3.ArithRef
    _h_active: bool = field(default=False)
    _concrete_items: dict[str, object] | None = field(default=None, compare=False)
    _has_default_factory: bool = field(default=False, compare=False)

    def __post_init__(self) -> None:
        if self._name:
            ln = self._name.lower()
            if ln in ("self", "cls") or ln.startswith(("self_", "cls_")):
                self._h_active = True

    __hash__ = object.__hash__

    @property
    def name(self) -> str:
        return self._name

    @property
    def is_dict(self) -> z3.BoolRef:
        return Z3_TRUE

    def to_z3(self) -> z3.ExprRef:
        return self.z3_array

    def copy(self) -> SymbolicDict:
        """Return a shallow copy of this symbolic dict."""
        import dataclasses

        return dataclasses.replace(self)

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
        # Use an Array as a Set (String -> Bool)
        known_keys = z3.Array(f"{name}_keys", z3.StringSort(), z3.BoolSort())
        z3_len = z3.Int(f"{name}_len")
        constraint = z3_len >= 0
        return SymbolicDict(name, z3_array, known_keys, z3_len), constraint

    @staticmethod
    def symbolic_int_dict(name: str | None = None) -> SymbolicDict:
        """Compatibility constructor used by newer call sites."""
        dict_name = name or fresh_name("dict")
        symbolic_dict, _ = SymbolicDict.symbolic(dict_name)
        return symbolic_dict

    @staticmethod
    def empty(name: str = "empty_dict") -> SymbolicDict:
        """Create an empty symbolic dict."""
        z3_array = z3.Array(f"{name}_dict", z3.StringSort(), z3.IntSort())
        known_keys = z3.K(z3.StringSort(), z3.BoolVal(False))
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

        presence_check = z3.Select(self.known_keys, sym_key.z3_str)
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
        )
        return val, cast(z3.BoolRef, presence_check)

    def __setitem__(self, key: object, value: object) -> SymbolicDict:
        """Dict assignment - returns new dict. Prevents redundant key growth."""
        sym_key = key if isinstance(key, SymbolicString) else SymbolicString.from_const(str(key))
        sym_value = value if isinstance(value, SymbolicValue) else SymbolicValue.from_const(value)
        new_array = z3.Store(
            self.z3_array,
            sym_key.z3_str,
            storage_int_expr(sym_value.z3_int, f"{self._name}_value"),
        )

        is_existing_key = z3.Select(self.known_keys, sym_key.z3_str)
        new_keys = z3.Store(self.known_keys, sym_key.z3_str, z3.BoolVal(True))

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
            _concrete_items=new_concrete,
        )

    def __delitem__(self, key: object) -> SymbolicDict:
        """Dict deletion - returns new dict.
        Updates known_keys and array to remove the entry.
        """
        sym_key = key if isinstance(key, SymbolicString) else SymbolicString.from_const(str(key))

        is_existing_key = z3.Select(self.known_keys, sym_key.z3_str)
        new_keys = z3.Store(self.known_keys, sym_key.z3_str, z3.BoolVal(False))

        new_len = z3.If(is_existing_key, self.z3_len - 1, self.z3_len)

        new_concrete = dict(self._concrete_items) if self._concrete_items is not None else None
        if new_concrete is not None and z3.is_string_value(sym_key.z3_str):
            key_str = sym_key.z3_str.as_string()
            if key_str in new_concrete:
                del new_concrete[key_str]

        return SymbolicDict(
            _name=f"del {self._name}[{sym_key.name}]",
            z3_array=self.z3_array,
            known_keys=new_keys,
            z3_len=new_len,
            _concrete_items=new_concrete,
        )

    def update(self, other: SymbolicDict | dict[str, object]) -> tuple[SymbolicDict, z3.BoolRef]:
        """Update dict - returns (new_dict, constraint)."""
        if isinstance(other, dict):
            res = self
            all_constraints: list[z3.BoolRef] = []
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

                other_has_k = z3.Select(other.known_keys, k)
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

                # New keys is union of self and other keys
                new_keys = cast(
                    "z3.ArrayRef",
                    z3.Lambda(
                        [k], z3.Or(z3.Select(self.known_keys, k), z3.Select(other.known_keys, k))
                    ),
                )

                new_len = z3.Int(fresh_name("updated_len"))

                max_len = z3.If(self.z3_len > other.z3_len, self.z3_len, other.z3_len)
                sum_len = self.z3_len + other.z3_len

                constraint = z3.And(new_len >= max_len, new_len <= sum_len)

                return SymbolicDict(
                    _name=f"{self._name}.update({other.name})",
                    z3_array=new_array,
                    known_keys=new_keys,
                    z3_len=new_len,
                ), constraint

    def contains_key(self, key: SymbolicString) -> SymbolicValue:
        """Check if key exists using the new Set-based (Array) model."""
        result = cast("z3.BoolRef", z3.Select(self.known_keys, key.z3_str))
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
        )

    def contains(self, key: SymbolicInt) -> z3.BoolRef:
        """Compatibility helper for collection abstractions."""
        key_expr = z3.IntToStr(key.z3_int)
        selected = z3.Select(self.known_keys, key_expr)
        if isinstance(selected, z3.BoolRef):
            return selected
        return z3.BoolVal(False)

    def __contains__(self, key: object) -> bool:
        """Dict membership check (concrete). Returns False for symbolic keys to avoid iteration."""
        return False

    @property
    def length(self) -> SymbolicValue:
        """Compatibility property used by collection helpers."""
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

    def conditional_merge(
        self, other: AnySymbolic, condition: z3.BoolRef
    ) -> SymbolicDict | SymbolicValue:
        """Merge with another dict based on condition.

        Optimized to only create z3.If() for fields that actually differ,
        reducing AST bloat.
        """
        if not isinstance(other, SymbolicDict):
            val_self = SymbolicValue.from_specialized(self)
            return val_self.conditional_merge(other, condition)

        if self is other:
            return self

        are_arrays_equal = self.z3_array is other.z3_array or safe_z3_eq(
            self.z3_array, other.z3_array
        )
        new_array = (
            self.z3_array if are_arrays_equal else z3.If(condition, self.z3_array, other.z3_array)
        )

        are_keys_equal = self.known_keys is other.known_keys or safe_z3_eq(
            self.known_keys, other.known_keys
        )
        new_keys = (
            self.known_keys
            if are_keys_equal
            else z3.If(condition, self.known_keys, other.known_keys)
        )

        are_lens_equal = self.z3_len is other.z3_len or safe_z3_eq(self.z3_len, other.z3_len)
        new_len = self.z3_len if are_lens_equal else z3.If(condition, self.z3_len, other.z3_len)

        return SymbolicDict(
            _name=f"If({condition}, {self._name}, {other.name})",
            z3_array=new_array,
            known_keys=new_keys,
            z3_len=new_len,
        )

    def __repr__(self) -> str:
        return f"SymbolicDict({self._name})"


import threading

BYTES_CONST_CACHE: dict[bytes, SymbolicBytes] = {}
BYTES_CONST_CACHE_LOCK = threading.Lock()
BYTES_CONST_CACHE_LIMIT: int = 1024


@dataclass
class SymbolicBytes(SymbolicType):
    """Symbolic bytes value backed by Z3 sequence theory."""

    z3_bytes: z3.SeqRef
    _name: str = ""

    __hash__ = object.__hash__

    @property
    def name(self) -> str:
        return self._name or "bytes"

    def to_z3(self) -> z3.ExprRef:
        return self.z3_bytes

    def hash_value(self) -> int:
        return self.z3_bytes.hash()

    def could_be_truthy(self) -> z3.BoolRef:
        return z3.Length(self.z3_bytes) > 0

    def could_be_falsy(self) -> z3.BoolRef:
        return z3.Length(self.z3_bytes) == 0

    @staticmethod
    def symbolic(name: str | None = None) -> SymbolicBytes:
        bytes_name = name or fresh_name("bytes")
        byte_sort = z3.BitVecSort(8)
        return SymbolicBytes(
            cast("z3.SeqRef", z3.Const(bytes_name, z3.SeqSort(byte_sort))), bytes_name
        )

    @staticmethod
    def concrete(value: bytes) -> SymbolicBytes:
        cached = BYTES_CONST_CACHE.get(value)
        if cached is not None:
            return cached

        byte_sort = z3.BitVecSort(8)
        if not value:
            sv = SymbolicBytes(z3.Empty(z3.SeqSort(byte_sort)), "b''")
        else:
            result = z3.Unit(z3.BitVecVal(value[0], 8))
            for b in value[1:]:
                result = z3.Concat(result, z3.Unit(z3.BitVecVal(b, 8)))
            sv = SymbolicBytes(result, repr(value))

        with BYTES_CONST_CACHE_LOCK:
            if len(BYTES_CONST_CACHE) < BYTES_CONST_CACHE_LIMIT:
                BYTES_CONST_CACHE[value] = sv
        return sv


@dataclass
class SymbolicTuple(SymbolicType):
    """Symbolic tuple representation used by collection helpers."""

    elements: tuple[object, ...]
    _name: str = ""

    __hash__ = object.__hash__

    @property
    def name(self) -> str:
        return self._name or "tuple"

    def to_z3(self) -> z3.ExprRef:
        if not self.elements:
            return Z3_ZERO
        head = self.elements[0]
        if isinstance(head, SymbolicType):
            return head.to_z3()
        if isinstance(head, int):
            return z3.IntVal(head)
        return Z3_ZERO

    def hash_value(self) -> int:
        return hash(self.elements)

    def could_be_truthy(self) -> z3.BoolRef:
        return z3.BoolVal(len(self.elements) > 0)

    def could_be_falsy(self) -> z3.BoolRef:
        return z3.BoolVal(len(self.elements) == 0)

    def __len__(self) -> int:
        return len(self.elements)

    def __getitem__(self, index: int | SymbolicInt) -> object:
        if isinstance(index, int):
            return self.elements[index]
        return SymbolicValue.from_const(0)

    def __iter__(self) -> Iterator[object]:
        return iter(self.elements)

    def __add__(self, other: SymbolicTuple) -> SymbolicTuple:
        return SymbolicTuple(self.elements + other.elements)

    @staticmethod
    def from_elements(*elements: object) -> SymbolicTuple:
        return SymbolicTuple(tuple(elements))

    @staticmethod
    def empty() -> SymbolicTuple:
        return SymbolicTuple(())


@dataclass
class SymbolicSet(SymbolicType):
    """Symbolic set backed by Z3 set theory."""

    z3_set: z3.ArrayRef
    element_sort: z3.SortRef
    _name: str = ""

    __hash__ = object.__hash__

    @property
    def name(self) -> str:
        return self._name or "set"

    def to_z3(self) -> z3.ExprRef:
        return self.z3_set

    def hash_value(self) -> int:
        return self.z3_set.hash()

    def could_be_truthy(self) -> z3.BoolRef:
        return self.length.value > 0

    def could_be_falsy(self) -> z3.BoolRef:
        return self.length.value == 0

    @property
    def length(self) -> SymbolicInt:
        if not hasattr(self, "_cached_length"):
            self._cached_length = SymbolicInt(z3.Int(fresh_name(f"set_len_{self.name}")))
        return self._cached_length

    def contains(self, elem: SymbolicInt) -> SymbolicBool:
        return SymbolicBool(z3.IsMember(elem.z3_int, self.z3_set))

    def add(self, elem: SymbolicInt) -> SymbolicSet:
        return SymbolicSet(z3.SetAdd(self.z3_set, elem.z3_int), self.element_sort)

    def remove(self, elem: SymbolicInt) -> SymbolicSet:
        return SymbolicSet(z3.SetDel(self.z3_set, elem.z3_int), self.element_sort)

    def union(self, other: SymbolicSet) -> SymbolicSet:
        return SymbolicSet(z3.SetUnion(self.z3_set, other.z3_set), self.element_sort)

    def intersection(self, other: SymbolicSet) -> SymbolicSet:
        return SymbolicSet(z3.SetIntersect(self.z3_set, other.z3_set), self.element_sort)

    def difference(self, other: SymbolicSet) -> SymbolicSet:
        return SymbolicSet(z3.SetDifference(self.z3_set, other.z3_set), self.element_sort)

    def issubset(self, other: SymbolicSet) -> SymbolicBool:
        return SymbolicBool(z3.IsSubset(self.z3_set, other.z3_set))

    @staticmethod
    def symbolic_int_set(name: str | None = None) -> SymbolicSet:
        set_name = name or fresh_name("set")
        return SymbolicSet(
            cast("z3.ArrayRef", z3.Const(set_name, z3.SetSort(z3.IntSort()))),
            z3.IntSort(),
            set_name,
        )

    @staticmethod
    def empty_int_set() -> SymbolicSet:
        return SymbolicSet(z3.EmptySet(z3.IntSort()), z3.IntSort(), "set()")


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
    model_name: str | None = field(default=None, compare=False)

    __hash__ = object.__hash__

    def __post_init__(self) -> None:
        """Post init."""
        if not self.potential_addresses and self.address != -1:
            self.potential_addresses = {self.address}
        if self._name:
            ln = self._name.lower()
            if ln in ("self", "cls") or ln.startswith(("self_", "cls_")):
                self._h_active = True

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

    @property
    def is_list(self) -> z3.BoolRef:
        """Property returning the is_list."""
        return Z3_FALSE

    @property
    def is_dict(self) -> z3.BoolRef:
        """Property returning the is_dict."""
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
        """Create from an existing object using its host identity as address."""
        addr = id(value)
        return SymbolicObject(f"obj_{addr}", addr, z3.IntVal(addr), {addr})

    def __eq__(self, other: object) -> SymbolicValue:  # type: ignore[override]  # Symbolic types return symbolic booleans, not Python bool
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

    def __ne__(self, other: object) -> SymbolicValue:  # type: ignore[override]  # Symbolic types return symbolic booleans, not Python bool
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
        """Merge with another object.

        Optimized to only create z3.If() for fields that actually differ,
        reducing AST bloat.
        """
        if isinstance(other, SymbolicNone):
            zero_val = z3.IntVal(0)
            are_addr_zero = self.z3_addr is zero_val or safe_z3_eq(self.z3_addr, zero_val)
            if are_addr_zero:
                return self
            new_addr = z3.If(condition, self.z3_addr, zero_val)
            return SymbolicObject(
                _name=f"If({condition}, {self._name}, None)",
                address=-1,
                z3_addr=new_addr,
                potential_addresses=self.potential_addresses.copy(),
            )
        if isinstance(other, SymbolicObject):
            if self is other:
                return self

            are_addr_equal = self.z3_addr is other.z3_addr or safe_z3_eq(
                self.z3_addr, other.z3_addr
            )
            new_addr = (
                self.z3_addr if are_addr_equal else z3.If(condition, self.z3_addr, other.z3_addr)
            )
            return SymbolicObject(
                _name=f"If({condition}, {self._name}, {other.name})",
                address=-1 if self.address != other.address else self.address,
                z3_addr=new_addr,
                potential_addresses=self.potential_addresses.union(other.potential_addresses),
            )
        val_self = SymbolicValue.from_specialized(self)
        return val_self.conditional_merge(other, condition)

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

    def remaining_bound(self) -> int | z3.ArithRef:
        """Calculate and return the remaining number of iterations."""
        if hasattr(self.iterable, "__len__"):
            length = len(self.iterable)  # type: ignore[arg-type]  # hasattr ensures __len__ exists
            return length - self.index
        unknown_remaining = z3.Int(f"{self._name}_remaining_{id(self)}")
        return z3.If(unknown_remaining >= 0, unknown_remaining, 0)
