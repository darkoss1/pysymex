"""Container and compound symbolic types for pysymex.

Provides SymbolicString, SymbolicList, SymbolicDict, SymbolicObject.
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
    SymbolicType,
    SymbolicValue,
    fresh_name,
)

if TYPE_CHECKING:
    from pysymex.core.types import AnySymbolic


def _raise_incompatible_merge(expected_type: str, other: object) -> None:
    actual_type = type(other).__name__
    raise TypeError(f"cannot conditionally merge {expected_type} with {actual_type}")


@dataclass
class SymbolicString(SymbolicType):
    """Symbolic string using Z3 string theory."""

    _name: str
    z3_str: z3.SeqRef
    z3_len: z3.ArithRef
    taint_labels: frozenset[str] | None = field(default=None, compare=False)

    __hash__ = object.__hash__

    @property
    def is_int(self) -> z3.BoolRef:
        return Z3_FALSE

    @property
    def is_bool(self) -> z3.BoolRef:
        return Z3_FALSE

    @property
    def is_str(self) -> z3.BoolRef:
        return Z3_TRUE

    @property
    def is_none(self) -> z3.BoolRef:
        return Z3_FALSE

    @property
    def is_obj(self) -> z3.BoolRef:
        return Z3_FALSE

    @property
    def is_path(self) -> z3.BoolRef:
        return Z3_FALSE

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_str

    def could_be_truthy(self) -> z3.BoolRef:
        return self.z3_len > 0

    def could_be_falsy(self) -> z3.BoolRef:
        return self.z3_len == 0

    def hash_value(self) -> int:
        """Stable hash based on Z3 string content."""
        return self.z3_str.hash()

    def with_taint(self, label: str | set[str] | frozenset[str]) -> SymbolicString:
        """Return a copy with added taint."""
        import dataclasses

        new_labels = set(self.taint_labels or set())
        if isinstance(label, str):
            new_labels.add(label)
        else:
            new_labels.update(label)
        return dataclasses.replace(self, taint_labels=frozenset(new_labels))

    @staticmethod
    def symbolic(name: str) -> tuple[SymbolicString, z3.BoolRef]:
        """Create a fresh symbolic string."""
        z3_str = z3.String(f"{name}_str")
        z3_len = z3.Length(z3_str)
        constraint = z3_len >= 0
        return SymbolicString(name, z3_str, z3_len), constraint

    @staticmethod
    def from_const(value: str) -> SymbolicString:
        """Create a concrete symbolic string."""
        z3_str = z3.StringVal(value)
        z3_len = z3.IntVal(len(value))
        return SymbolicString(repr(value), z3_str, z3_len)

    def __add__(self, other: SymbolicString) -> SymbolicString:
        """String concatenation."""
        return SymbolicString(
            _name=f"({self._name}+{other.name})",
            z3_str=z3.Concat(self.z3_str, other.z3_str),
            z3_len=self.z3_len + other.z3_len,
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def __getitem__(self, index: SymbolicValue) -> SymbolicString:
        """String indexing with negative wrap-around support."""

        real_idx = z3.If(index.z3_int < 0, index.z3_int + self.z3_len, index.z3_int)
        return SymbolicString(
            _name=f"{self._name}[{index.name}]",
            z3_str=z3.SubString(self.z3_str, real_idx, z3.IntVal(1)),
            z3_len=z3.IntVal(1),
            taint_labels=(self.taint_labels or frozenset()) | (index.taint_labels or frozenset()),
        )

    def substring(self, start: SymbolicValue, length: SymbolicValue) -> SymbolicString:
        """Extract substring."""
        return SymbolicString(
            _name=f"{self._name}[{start.name}:{start.name}+{length.name}]",
            z3_str=z3.SubString(self.z3_str, start.z3_int, length.z3_int),
            z3_len=length.z3_int,
            taint_labels=(self.taint_labels or frozenset())
            | (start.taint_labels or frozenset())
            | (length.taint_labels or frozenset()),
        )

    def contains(self, other: SymbolicString) -> SymbolicValue:
        """Check if string contains another string."""
        result = z3.Contains(self.z3_str, other.z3_str)
        return SymbolicValue(
            _name=f"({other.name} in {self._name})",
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=result,
            is_bool=Z3_TRUE,
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def index_of(self, other: SymbolicString) -> SymbolicValue:
        """Find index of substring."""
        idx = z3.IndexOf(self.z3_str, other.z3_str, z3.IntVal(0))
        return SymbolicValue(
            _name=f"{self._name}.index({other.name})",
            z3_int=idx,
            is_int=Z3_TRUE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def length(self) -> SymbolicValue:
        """Get string length."""
        return SymbolicValue(
            _name=f"len({self._name})",
            z3_int=self.z3_len,
            is_int=Z3_TRUE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
        )

    def hash_value(self) -> int:
        return self.z3_str.hash() ^ self.z3_len.hash()

    def startswith(self, prefix: str | SymbolicString) -> SymbolicValue:
        """Check if string starts with prefix."""
        if isinstance(prefix, str):
            prefix_z3 = z3.StringVal(prefix)
            prefix_name = repr(prefix)
        else:
            prefix_z3 = prefix.z3_str
            prefix_name = prefix.name

        result = z3.PrefixOf(prefix_z3, self.z3_str)
        return SymbolicValue(
            _name=f"{self._name}.startswith({prefix_name})",
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=result,
            is_bool=Z3_TRUE,
            taint_labels=self.taint_labels,
        )

    def __eq__(self, other: object) -> SymbolicValue:
        if not isinstance(other, SymbolicString):
            return SymbolicValue.from_const(False)
        return SymbolicValue(
            _name=f"({self._name}=={other.name})",
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=self.z3_str == other.z3_str,
            is_bool=Z3_TRUE,
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def conditional_merge(self, other: AnySymbolic, condition: z3.BoolRef) -> AnySymbolic:
        """Merge with another value based on condition."""
        if isinstance(other, SymbolicString):
            new_str = z3.If(condition, self.z3_str, other.z3_str)
            new_len = z3.If(condition, self.z3_len, other.z3_len)
            return SymbolicString(
                _name=f"If({condition}, {self._name}, {other.name})",
                z3_str=new_str,
                z3_len=new_len,
                taint_labels=(self.taint_labels or frozenset())
                | (other.taint_labels or frozenset()),
            )

        val_self = SymbolicValue(
            _name=self._name,
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            z3_str=self.z3_str,
            is_str=Z3_TRUE,
            taint_labels=self.taint_labels,
        )
        return val_self.conditional_merge(other, condition)

    def __repr__(self) -> str:
        return f"SymbolicString({self._name})"

    def as_unified(self) -> SymbolicValue:
        from .types import Z3_FALSE, Z3_TRUE, Z3_ZERO, SymbolicValue

        return SymbolicValue(
            _name=self._name,
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            z3_str=self.z3_str,
            is_str=Z3_TRUE,
            is_obj=Z3_FALSE,
            is_list=Z3_FALSE,
            is_dict=Z3_FALSE,
            is_path=Z3_FALSE,
            is_none=Z3_FALSE,
            taint_labels=self.taint_labels,
        )


@dataclass
class SymbolicList(SymbolicType):
    """Symbolic list using Z3 arrays and explicit length tracking.
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
        new_array = z3.Store(self.z3_array, index.z3_int, value.z3_int)
        return SymbolicList(
            _name=f"{self._name}[{index.name}]={value.name}",
            z3_array=new_array,
            z3_len=self.z3_len,
            element_type=self.element_type,
            taint_labels=(self.taint_labels or frozenset())
            | (index.taint_labels or frozenset())
            | (value.taint_labels or frozenset()),
        )

    def append(self, value: SymbolicValue) -> SymbolicList:
        """Append element - returns new list."""
        new_array = z3.Store(self.z3_array, self.z3_len, value.z3_int)
        return SymbolicList(
            _name=f"{self._name}.append({value.name})",
            z3_array=new_array,
            z3_len=self.z3_len + 1,
            element_type=self.element_type,
            taint_labels=(self.taint_labels or frozenset()) | (value.taint_labels or frozenset()),
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
        """Check if index is valid."""
        return z3.And(index.z3_int >= 0, index.z3_int < self.z3_len)

    def conditional_merge(self, other: AnySymbolic, condition: z3.BoolRef) -> SymbolicList:
        """Merge with another list based on condition."""
        if not isinstance(other, SymbolicList):
            val_self = SymbolicValue(
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
                taint_labels=self.taint_labels,
            )
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
        from .types import Z3_FALSE, Z3_TRUE, Z3_ZERO, SymbolicValue

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
            taint_labels=self.taint_labels,
        )


@dataclass
class SymbolicDict(SymbolicType):
    """Symbolic dictionary using Z3 arrays.
    For simplicity, we model string-keyed dicts with int values.
    """

    _name: str
    z3_array: z3.ArrayRef
    known_keys: z3.SeqRef
    z3_len: z3.ArithRef
    taint_labels: set[str] | frozenset[str] | None = field(default=None, compare=False)

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
        new_keys = z3.If(
            z3.Contains(self.known_keys, key_unit),
            self.known_keys,
            z3.Concat(self.known_keys, key_unit),
        )
        return SymbolicDict(
            _name=f"{self._name}[{key.name}]={value.name}",
            z3_array=new_array,
            known_keys=new_keys,
            z3_len=self.z3_len,
            taint_labels=(self.taint_labels or frozenset())
            | (key.taint_labels or frozenset())
            | (value.taint_labels or frozenset()),
        )

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
        # This prevents Python from falling back to __getitem__(0), __getitem__(1)...
        # when 'in' is used on a SymbolicDict.
        return False

    def conditional_merge(self, other: AnySymbolic, condition: z3.BoolRef) -> AnySymbolic:
        """Merge with another dict based on condition."""
        if not isinstance(other, SymbolicDict):
            val_self = SymbolicValue(
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
                taint_labels=self.taint_labels,
            )
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
        from .types import Z3_FALSE, Z3_TRUE, Z3_ZERO, SymbolicValue

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

    __hash__ = object.__hash__

    def __post_init__(self):
        if not self.potential_addresses and self.address != -1:
            self.potential_addresses = {self.address}

    @property
    def name(self) -> str:
        return self._name

    @property
    def is_int(self) -> z3.BoolRef:
        return Z3_FALSE

    @property
    def is_bool(self) -> z3.BoolRef:
        return Z3_FALSE

    @property
    def is_str(self) -> z3.BoolRef:
        return Z3_FALSE

    @property
    def is_none(self) -> z3.BoolRef:
        return Z3_FALSE

    @property
    def is_obj(self) -> z3.BoolRef:
        return Z3_TRUE

    @property
    def is_path(self) -> z3.BoolRef:
        return Z3_FALSE

    def to_z3(self) -> z3.ExprRef:
        return self.z3_addr

    def hash_value(self) -> int:
        return self.z3_addr.hash()

    def could_be_truthy(self) -> z3.BoolRef:
        return self.z3_addr != 0

    def could_be_falsy(self) -> z3.BoolRef:
        return self.z3_addr == 0

    @staticmethod
    def symbolic(name: str, address: int) -> tuple[SymbolicObject, z3.BoolRef]:
        """Create a fresh symbolic object pointer."""
        z3_addr = z3.IntVal(address)
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
        If address is same, we assume object identity is same (merging state handled by caller/heap).
        If address differs, we create a symbolic pointer: If(cond, addr1, addr2).
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
        # If other is not SymbolicObject or SymbolicNone, merge into a SymbolicValue
        val_self = SymbolicValue(
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
            is_path=Z3_FALSE,
            is_none=Z3_FALSE,
        )
        return val_self.conditional_merge(other, condition)

    def as_unified(self) -> SymbolicValue:
        from .types import Z3_FALSE, Z3_TRUE, Z3_ZERO, SymbolicValue

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
            taint_labels=None,
        )


@dataclass
class SymbolicIterator(SymbolicType):
    """Symbolic iterator tracking the source sequence."""

    _name: str
    iterable: object
    index: int = 0

    __hash__ = object.__hash__

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
        return f"SymbolicIterator(of {self.iterable})"

    def as_unified(self) -> SymbolicValue:
        from .types import Z3_FALSE, Z3_ZERO, SymbolicValue

        return SymbolicValue(
            _name=self._name,
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_path=Z3_FALSE,
        )
