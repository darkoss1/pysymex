"""Container and compound symbolic types for pysymex.

Provides SymbolicList, SymbolicDict, SymbolicObject.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import z3

from pysymex.core.types import (
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


def _raise_incompatible_merge(expected_type: str, other: object) -> None:
    """Raise incompatible merge."""
    actual_type = type(other).__name__
    raise TypeError(f"cannot conditionally merge {expected_type} with {actual_type}")


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
    taint_labels: set[str] | frozenset[str] | None = field(default=None, compare=False)
    _h_active: bool = field(default=False)
    _concrete_items: list[object] | None = field(default=None, compare=False)

    def __post_init__(self):
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

    def __getitem__(self, index: SymbolicValue) -> SymbolicValue:
        """List indexing with negative wrap-around support."""
        if not isinstance(index, SymbolicValue):
            index = SymbolicValue.from_const(index)
        real_idx = z3.If(index.z3_int < 0, index.z3_int + self.z3_len, index.z3_int)
        elem = z3.Select(self.z3_array, real_idx)
        return SymbolicValue(
            _name=f"{self._name}[{index.name}]",
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
            taint_labels=(self.taint_labels or frozenset()) | (index.taint_labels or frozenset()),
        )

    def __setitem__(self, index: SymbolicValue, value: SymbolicValue) -> SymbolicList:
        """List assignment - returns new list (immutable semantics)."""
        if not isinstance(index, SymbolicValue):
            index = SymbolicValue.from_const(index)
        if not isinstance(value, SymbolicValue):
            value = SymbolicValue.from_const(value)
        real_idx = z3.If(index.z3_int < 0, index.z3_int + self.z3_len, index.z3_int)
        new_array = z3.Store(self.z3_array, real_idx, value.z3_int)
        new_concrete = list(self._concrete_items) if self._concrete_items is not None else None
        if new_concrete is not None and z3.is_int_value(index.z3_int):
            idx = index.z3_int.as_long()
            if 0 <= idx < len(new_concrete):
                new_concrete[idx] = value
            else:
                new_concrete = None
        else:
            new_concrete = None

        return SymbolicList(
            _name=f"{self._name}[{index.name}]={value.name}",
            z3_array=new_array,
            z3_len=self.z3_len,
            element_type=self.element_type,
            taint_labels=(self.taint_labels or frozenset())
            | (index.taint_labels or frozenset())
            | (value.taint_labels or frozenset()),
            _concrete_items=new_concrete,
        )

    def append(self, value: SymbolicValue) -> SymbolicList:
        """Append element - returns new list."""
        new_array = z3.Store(self.z3_array, self.z3_len, (value.z3_int if hasattr(value, "z3_int") else z3.IntVal(0)) if value is not None else z3.IntVal(0))
        new_concrete = list(self._concrete_items) if self._concrete_items is not None else None
        if new_concrete is not None:
            new_concrete.append(value)
        return SymbolicList(
            _name=f"{self._name}.append({getattr(value, 'name', 'None')})",
            z3_array=new_array,
            z3_len=self.z3_len + 1,
            element_type=self.element_type,
            taint_labels=(self.taint_labels or frozenset()) | (getattr(value, 'taint_labels', frozenset()) or frozenset()),
            _concrete_items=new_concrete,
        )

    def extend(self, other: SymbolicList | list | tuple) -> SymbolicList:
        """Extend list - returns new list."""
        if isinstance(other, (list, tuple)):
            res = self
            for item in other:
                s_item = item if hasattr(item, "z3_int") else SymbolicValue.from_const(item)
                res = res.append(s_item)
            return res
        elif isinstance(other, SymbolicList):
            if other._concrete_items is not None:
                res = self
                for item in other._concrete_items:
                    s_item = item if hasattr(item, "z3_int") else SymbolicValue.from_const(item)
                    res = res.append(s_item)
                return res
            else:
                # Symbolic merge: use a conditional select logic
                # For simplicity, we use a fresh array and constrain it, 
                # but Z3 doesn't support 'copy' well. 
                # Better: return a wrapper or use a lambda if possible.
                # However, pysymex usually prefers ArrayRef.
                # Let's use a Lambda to represent the concatenated array.
                idx = z3.Int(fresh_name("i"))
                new_array = z3.Lambda([idx], z3.If(idx < self.z3_len, 
                                                z3.Select(self.z3_array, idx), 
                                                z3.Select(other.z3_array, idx - self.z3_len)))
                return SymbolicList(
                    _name=f"{self._name}.extend({other.name})",
                    z3_array=new_array,
                    z3_len=self.z3_len + other.z3_len,
                    element_type=self.element_type,
                    taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
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

    def conditional_merge(self, other: AnySymbolic, condition: z3.BoolRef) -> SymbolicList:
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
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def __repr__(self) -> str:
        return f"SymbolicList({self._name}, len={self.z3_len})"

    def as_unified(self) -> SymbolicValue:
        """As unified."""
        from .types import SymbolicValue
        return SymbolicValue(
            _name=self._name,
            z3_int=Z3_ZERO,
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
    taint_labels: set[str] | frozenset[str] | None = field(default=None, compare=False)
    _h_active: bool = field(default=False)
    _concrete_items: dict[str, object] | None = field(default=None, compare=False)

    def __post_init__(self):
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

    def __getitem__(self, key: SymbolicString) -> tuple[SymbolicValue, z3.BoolRef]:
        """Dict lookup. Returns (value, presence_check)."""
        if not isinstance(key, SymbolicString):
            key = SymbolicString.from_const(key)
        elem = z3.Select(self.z3_array, key.z3_str)

        presence_check = z3.Contains(self.known_keys, z3.Unit(key.z3_str))
        val = SymbolicValue(
            _name=f"{self._name}[{key.name}]",
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
            taint_labels=(self.taint_labels or frozenset()) | (key.taint_labels or frozenset()),
        )
        return val, presence_check

    def __setitem__(self, key: SymbolicString, value: SymbolicValue) -> SymbolicDict:
        """Dict assignment - returns new dict. Prevents redundant key growth."""
        if not isinstance(key, SymbolicString):
            key = SymbolicString.from_const(key)
        if not isinstance(value, SymbolicValue):
            value = SymbolicValue.from_const(value)
        new_array = z3.Store(self.z3_array, key.z3_str, value.z3_int)
        key_unit = z3.Unit(key.z3_str)
        is_existing_key = z3.Contains(self.known_keys, key_unit)
        new_keys = z3.If(
            is_existing_key,
            self.known_keys,
            z3.Concat(self.known_keys, key_unit),
        )
        new_len = z3.If(is_existing_key, self.z3_len, self.z3_len + 1)
        new_concrete = dict(self._concrete_items) if self._concrete_items is not None else None
        if new_concrete is not None and z3.is_string_value(key.z3_str):
            new_concrete[key.z3_str.as_string()] = value
        else:
            new_concrete = None

        return SymbolicDict(
            _name=f"{self._name}[{key.name}]={value.name}",
            z3_array=new_array,
            known_keys=new_keys,
            z3_len=new_len,
            taint_labels=(self.taint_labels or frozenset())
            | (key.taint_labels or frozenset())
            | (value.taint_labels or frozenset()),
            _concrete_items=new_concrete,
        )

    def update(self, other: SymbolicDict | dict) -> tuple[SymbolicDict, z3.BoolRef]:
        """Update dict - returns (new_dict, constraint)."""
        if isinstance(other, dict):
            res = self
            all_constraints = []
            for k, v in other.items():
                # self.__setitem__ returns a new SymbolicDict
                res = res.__setitem__(k, v)
            return res, z3.And(*all_constraints) if all_constraints else z3.BoolVal(True)
        elif isinstance(other, SymbolicDict):
            if other._concrete_items is not None:
                res = self
                for k, v in other._concrete_items.items():
                    res = res.__setitem__(k, v)
                return res, z3.BoolVal(True)
            else:
                k = z3.String(fresh_name("k"))
                # If key is in 'other', use other's value, else use self's value.
                other_has_k = z3.Contains(other.known_keys, z3.Unit(k))
                new_array = z3.Lambda([k], z3.If(other_has_k,
                                               z3.Select(other.z3_array, k),
                                               z3.Select(self.z3_array, k)))
                new_keys = z3.Concat(self.known_keys, other.known_keys)
                
                new_len = z3.Int(fresh_name("updated_len"))
                # Length is at least max(len1, len2) and at most len1 + len2
                max_len = z3.If(self.z3_len > other.z3_len, self.z3_len, other.z3_len)
                sum_len = self.z3_len + other.z3_len
                
                constraint = z3.And(new_len >= max_len, new_len <= sum_len)
                
                return SymbolicDict(
                    _name=f"{self._name}.update({other.name})",
                    z3_array=new_array,
                    known_keys=new_keys,
                    z3_len=new_len,
                    taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
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
            taint_labels=(self.taint_labels or frozenset()) | (key.taint_labels or frozenset()),
        )

    def __contains__(self, key: object) -> bool:
        """Dict membership check (concrete). Returns False for symbolic keys to avoid iteration."""
        return False

    def conditional_merge(self, other: AnySymbolic, condition: z3.BoolRef) -> SymbolicDict:
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
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def __repr__(self) -> str:
        return f"SymbolicDict({self._name})"

    def as_unified(self) -> SymbolicValue:
        """As unified."""
        from .types import SymbolicValue
        return SymbolicValue(
            _name=self._name,
            z3_int=Z3_ZERO,
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

    def __post_init__(self):
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
        z3_addr = z3.Int(f"{name}_addr")
        constraint = Z3_TRUE
        return SymbolicObject(name, address, z3_addr, {address}), constraint

    @staticmethod
    def from_const(value: object) -> SymbolicObject:
        """Create from existing object (requires address management - usually caller handles this)."""
        addr = id(value)
        return SymbolicObject(f"obj_{addr}", addr, z3.IntVal(addr), {addr})

    def __eq__(self, other: object) -> SymbolicValue:
        if not isinstance(other, SymbolicObject):
            if isinstance(other, SymbolicNone):
                return SymbolicValue(
                    _name=f"({self._name} is None)",
                    z3_int=Z3_ZERO,
                    is_int=Z3_FALSE,
                    z3_bool=self.z3_addr == 0,
                    is_bool=Z3_TRUE,
                    is_str=Z3_FALSE,
                    is_obj=Z3_FALSE,
                    is_list=Z3_FALSE,
                    is_dict=Z3_FALSE,
                    is_path=Z3_FALSE,
                    is_none=Z3_FALSE,
                )
            return SymbolicValue.from_const(False)
        return SymbolicValue(
            _name=f"({self._name}=={other.name})",
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=self.z3_addr == other.z3_addr,
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
        """
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
        from .types import SymbolicValue
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
        from .types import SymbolicValue
        return SymbolicValue(
            _name=self._name,
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_path=Z3_FALSE,
        )
