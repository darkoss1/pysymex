"""Symbolic container types: String, Bytes, Tuple, List, Dict, Set.

Each type maps Python container semantics to Z3 theories:
- SymbolicString: Z3 String theory
- SymbolicBytes: Z3 Sequence of BitVec(8)
- SymbolicTuple: Fixed-length heterogeneous elements
- SymbolicList: Z3 Sequence theory (homogeneous)
- SymbolicDict: Z3 Array theory
- SymbolicSet: Z3 Set theory
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import cast

import z3

from .symbolic_types_base import SymbolicType, TypeTag, fresh_name
from .symbolic_types_numeric import SymbolicBool, SymbolicInt


@dataclass
class SymbolicString(SymbolicType):
    """Symbolic string value.
    Uses Z3's String theory for precise string reasoning.
    """

    z3_str: z3.SeqRef
    _name: str = field(default="")

    def __post_init__(self):
        if not self._name:
            self._name = fresh_name("str")

    @property
    def type_tag(self) -> TypeTag:
        return TypeTag.STRING

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_str

    def is_truthy(self) -> z3.BoolRef:
        return z3.Length(self.z3_str) > 0

    def is_falsy(self) -> z3.BoolRef:
        return z3.Length(self.z3_str) == 0

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        if isinstance(other, SymbolicString):
            return self.z3_str == other.z3_str
        return z3.BoolVal(False)

    def length(self) -> SymbolicInt:
        """Return symbolic length."""
        return SymbolicInt(z3.Length(self.z3_str))

    def __add__(self, other: SymbolicString) -> SymbolicString:
        """String concatenation."""
        return SymbolicString(z3.Concat(self.z3_str, other.z3_str))

    def __mul__(self, n: SymbolicInt) -> SymbolicString:
        """String repetition."""

        if z3.is_int_value(n.z3_int):
            count = n.z3_int.as_long()
            if count <= 0:
                return SymbolicString.concrete("")
            result = self.z3_str
            for _ in range(min(count - 1, 1000)):
                result = z3.Concat(result, self.z3_str)
            return SymbolicString(result)

        result_name = fresh_name(f"strmul_{self._name}")
        return SymbolicString(z3.String(result_name), result_name)

    def __getitem__(self, index: SymbolicInt) -> SymbolicString:
        """Character access."""
        return SymbolicString(z3.SubString(self.z3_str, index.z3_int, 1))

    def contains(self, other: SymbolicString) -> SymbolicBool:
        """Substring check."""
        return SymbolicBool(z3.Contains(self.z3_str, other.z3_str))

    def startswith(self, prefix: SymbolicString) -> SymbolicBool:
        """Check if string starts with prefix."""
        return SymbolicBool(z3.PrefixOf(prefix.z3_str, self.z3_str))

    def endswith(self, suffix: SymbolicString) -> SymbolicBool:
        """Check if string ends with suffix."""
        return SymbolicBool(z3.SuffixOf(suffix.z3_str, self.z3_str))

    def find(self, sub: SymbolicString) -> SymbolicInt:
        """Find index of substring (-1 if not found)."""
        return SymbolicInt(z3.IndexOf(self.z3_str, sub.z3_str, 0))

    def slice(self, start: SymbolicInt, length: SymbolicInt) -> SymbolicString:
        """Get substring."""
        return SymbolicString(z3.SubString(self.z3_str, start.z3_int, length.z3_int))

    def replace(self, old: SymbolicString, new: SymbolicString) -> SymbolicString:
        """Replace first occurrence."""
        return SymbolicString(z3.Replace(self.z3_str, old.z3_str, new.z3_str))

    def __lt__(self, other: SymbolicString) -> SymbolicBool:
        """Lexicographic comparison."""
        return SymbolicBool(self.z3_str < other.z3_str)

    def __le__(self, other: SymbolicString) -> SymbolicBool:
        return SymbolicBool(self.z3_str <= other.z3_str)

    def __gt__(self, other: SymbolicString) -> SymbolicBool:
        return SymbolicBool(self.z3_str > other.z3_str)

    def __ge__(self, other: SymbolicString) -> SymbolicBool:
        return SymbolicBool(self.z3_str >= other.z3_str)

    def __eq__(self, other: object) -> SymbolicBool:
        if isinstance(other, SymbolicString):
            return SymbolicBool(self.z3_str == other.z3_str)
        return SymbolicBool.concrete(False)

    def __ne__(self, other: object) -> SymbolicBool:
        eq = self.__eq__(other)
        return SymbolicBool(z3.Not(eq.z3_bool))

    @staticmethod
    def symbolic(name: str | None = None) -> SymbolicString:
        """Create a fresh symbolic string."""
        name = name or fresh_name("str")
        return SymbolicString(z3.String(name), name)

    @staticmethod
    def concrete(value: str) -> SymbolicString:
        """Create a concrete string."""
        return SymbolicString(z3.StringVal(value), repr(value))


@dataclass
class SymbolicBytes(SymbolicType):
    """Symbolic bytes value.
    Uses Z3's Sequence theory with bitvectors for byte-level operations.
    """

    z3_bytes: z3.SeqRef
    _name: str = field(default="")

    def __post_init__(self):
        if not self._name:
            self._name = fresh_name("bytes")

    @property
    def type_tag(self) -> TypeTag:
        return TypeTag.BYTES

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_bytes

    def is_truthy(self) -> z3.BoolRef:
        return z3.Length(self.z3_bytes) > 0

    def is_falsy(self) -> z3.BoolRef:
        return z3.Length(self.z3_bytes) == 0

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        if isinstance(other, SymbolicBytes):
            return self.z3_bytes == other.z3_bytes
        return z3.BoolVal(False)

    def length(self) -> SymbolicInt:
        """Return symbolic length."""
        return SymbolicInt(z3.Length(self.z3_bytes))

    def __add__(self, other: SymbolicBytes) -> SymbolicBytes:
        """Bytes concatenation."""
        return SymbolicBytes(z3.Concat(self.z3_bytes, other.z3_bytes))

    @staticmethod
    def symbolic(name: str | None = None) -> SymbolicBytes:
        """Create a fresh symbolic bytes object."""
        name = name or fresh_name("bytes")
        byte_sort = z3.BitVecSort(8)
        return SymbolicBytes(cast("z3.SeqRef", z3.Const(name, z3.SeqSort(byte_sort))), name)

    @staticmethod
    def concrete(value: bytes) -> SymbolicBytes:
        """Create concrete bytes."""
        byte_sort = z3.BitVecSort(8)
        if len(value) == 0:
            return SymbolicBytes(z3.Empty(z3.SeqSort(byte_sort)), "b''")
        result = z3.Unit(z3.BitVecVal(value[0], 8))
        for b in value[1:]:
            result = z3.Concat(result, z3.Unit(z3.BitVecVal(b, 8)))
        return SymbolicBytes(result, repr(value))


@dataclass
class SymbolicTuple(SymbolicType):
    """Symbolic tuple - fixed-length, heterogeneous.
    Each element is a separate symbolic value.
    """

    elements: tuple[SymbolicType, ...]
    _name: str = field(default="")

    def __post_init__(self):
        if not self._name:
            self._name = fresh_name("tuple")

    @property
    def _elements(self) -> tuple[SymbolicType, ...]:
        """Alias for elements (used by collections module)."""
        return self.elements

    @property
    def type_tag(self) -> TypeTag:
        return TypeTag.TUPLE

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        if self.elements:
            return self.elements[0].to_z3()
        return z3.IntVal(0)

    def is_truthy(self) -> z3.BoolRef:
        return z3.BoolVal(len(self.elements) > 0)

    def is_falsy(self) -> z3.BoolRef:
        return z3.BoolVal(len(self.elements) == 0)

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        if isinstance(other, SymbolicTuple):
            if len(self.elements) != len(other.elements):
                return z3.BoolVal(False)
            if not self.elements:
                return z3.BoolVal(True)
            conditions = [
                a.symbolic_eq(b) for a, b in zip(self.elements, other.elements, strict=False)
            ]
            return z3.And(*conditions)
        return z3.BoolVal(False)

    def length(self) -> SymbolicInt:
        """Return concrete length."""
        return SymbolicInt.concrete(len(self.elements))

    def __len__(self) -> int:
        return len(self.elements)

    def __getitem__(self, index: int | SymbolicInt) -> SymbolicType:
        if isinstance(index, int):
            return self.elements[index]
        result_name = fresh_name(f"tuple_elem_{self._name}")
        return SymbolicInt(z3.Int(result_name), result_name)

    def __iter__(self) -> Iterator[SymbolicType]:
        return iter(self.elements)

    def __add__(self, other: SymbolicTuple) -> SymbolicTuple:
        """Tuple concatenation."""
        return SymbolicTuple(self.elements + other.elements)

    @staticmethod
    def from_elements(*elements: SymbolicType) -> SymbolicTuple:
        """Create a tuple from elements."""
        return SymbolicTuple(tuple(elements))

    @staticmethod
    def empty() -> SymbolicTuple:
        """Create empty tuple."""
        return SymbolicTuple(())


@dataclass
class SymbolicList(SymbolicType):
    """Symbolic list - variable-length, homogeneous.
    Uses Z3 Sequence theory for precise list operations.
    """

    z3_seq: z3.SeqRef
    element_sort: z3.SortRef
    _name: str = field(default="")

    def __post_init__(self):
        if not self._name:
            self._name = fresh_name("list")

    @property
    def type_tag(self) -> TypeTag:
        return TypeTag.LIST

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_seq

    def is_truthy(self) -> z3.BoolRef:
        return z3.Length(self.z3_seq) > 0

    def is_falsy(self) -> z3.BoolRef:
        return z3.Length(self.z3_seq) == 0

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        if isinstance(other, SymbolicList):
            return self.z3_seq == other.z3_seq
        return z3.BoolVal(False)

    def length(self) -> SymbolicInt:
        """Return symbolic length."""
        return SymbolicInt(z3.Length(self.z3_seq))

    def __getitem__(self, index: SymbolicInt | int | z3.ArithRef) -> SymbolicInt:
        """Element access using Z3 sequence Nth."""
        if isinstance(index, int):
            idx = z3.IntVal(index)
        elif isinstance(index, SymbolicInt):
            idx = index.z3_int
        else:
            idx = index
        return SymbolicInt(cast("z3.ArithRef", self.z3_seq[idx]))

    def __add__(self, other: SymbolicList) -> SymbolicList:
        """List concatenation."""
        return SymbolicList(z3.Concat(self.z3_seq, other.z3_seq), self.element_sort)

    def append(self, elem: SymbolicInt) -> SymbolicList:
        """Return new list with element appended."""
        return SymbolicList(z3.Concat(self.z3_seq, z3.Unit(elem.z3_int)), self.element_sort)

    def contains(self, elem: SymbolicInt) -> SymbolicBool:
        """Check if element is in list."""
        return SymbolicBool(z3.Contains(self.z3_seq, z3.Unit(elem.z3_int)))

    def slice(self, start: SymbolicInt, length: SymbolicInt) -> SymbolicList:
        """Get sublist."""
        return SymbolicList(z3.Extract(self.z3_seq, start.z3_int, length.z3_int), self.element_sort)

    @staticmethod
    def symbolic_int_list(name: str | None = None) -> SymbolicList:
        """Create a fresh symbolic list of integers."""
        name = name or fresh_name("list")
        int_seq_sort = z3.SeqSort(z3.IntSort())
        return SymbolicList(cast("z3.SeqRef", z3.Const(name, int_seq_sort)), z3.IntSort(), name)

    @staticmethod
    def concrete_int_list(values: list[int]) -> SymbolicList:
        """Create a concrete list of integers."""
        int_seq_sort = z3.SeqSort(z3.IntSort())
        if not values:
            return SymbolicList(z3.Empty(int_seq_sort), z3.IntSort(), "[]")
        result = z3.Unit(z3.IntVal(values[0]))
        for v in values[1:]:
            result = z3.Concat(result, z3.Unit(z3.IntVal(v)))
        return SymbolicList(result, z3.IntSort(), str(values))


@dataclass
class SymbolicDict(SymbolicType):
    """Symbolic dictionary.
    Uses Z3 Array theory: Dict[K, V] -> Array(K, Option[V])
    A parallel boolean array ``_membership`` tracks which keys exist.
    """

    z3_array: z3.ArrayRef
    key_sort: z3.SortRef
    value_sort: z3.SortRef
    _name: str = field(default="")
    _membership: z3.ArrayRef | None = field(default=None, repr=False)

    def __post_init__(self):
        if not self._name:
            self._name = fresh_name("dict")
        if self._membership is None:
            self._membership = z3.K(self.key_sort, False)

    @property
    def type_tag(self) -> TypeTag:
        return TypeTag.DICT

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_array

    def is_truthy(self) -> z3.BoolRef:
        if not hasattr(self, "_cached_truthy"):
            self._cached_truthy: z3.BoolRef = z3.Bool(fresh_name(f"dict_nonempty_{self._name}"))
        return self._cached_truthy

    def is_falsy(self) -> z3.BoolRef:
        return z3.Not(self.is_truthy())

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        if isinstance(other, SymbolicDict):
            return self.z3_array == other.z3_array
        return z3.BoolVal(False)

    def __getitem__(self, key: SymbolicInt) -> SymbolicInt:
        """Dictionary lookup."""
        return SymbolicInt(cast("z3.ArithRef", z3.Select(self.z3_array, key.z3_int)))

    def __setitem__(self, key: SymbolicInt, value: SymbolicInt) -> SymbolicDict:
        """Return new dict with updated key."""
        new_arr = z3.Store(self.z3_array, key.z3_int, value.z3_int)
        new_mem = z3.Store(self._membership, key.z3_int, True)
        return SymbolicDict(new_arr, self.key_sort, self.value_sort, _membership=new_mem)

    def get(self, key: SymbolicInt, default: SymbolicInt) -> SymbolicInt:
        """Get with default — returns default when key is absent."""
        has_key = z3.Select(self._membership, key.z3_int)
        return SymbolicInt(
            cast(
                "z3.ArithRef", z3.If(has_key, z3.Select(self.z3_array, key.z3_int), default.z3_int)
            )
        )

    @property
    def length(self) -> SymbolicInt:
        """Return symbolic cardinality (conservative approximation)."""
        if not hasattr(self, "_cached_length"):
            self._cached_length: SymbolicInt = SymbolicInt(
                z3.Int(fresh_name(f"dict_len_{self._name}"))
            )
        return self._cached_length

    def contains(self, key: SymbolicInt) -> z3.BoolRef:
        """Check if key exists using membership array."""
        return z3.Select(self._membership, key.z3_int)

    @staticmethod
    def symbolic_int_dict(name: str | None = None) -> SymbolicDict:
        """Create a fresh symbolic dict with int keys and int values."""
        name = name or fresh_name("dict")
        array_sort = z3.ArraySort(z3.IntSort(), z3.IntSort())
        membership = z3.K(z3.IntSort(), False)
        return SymbolicDict(
            cast("z3.ArrayRef", z3.Const(name, array_sort)),
            z3.IntSort(),
            z3.IntSort(),
            name,
            _membership=membership,
        )


@dataclass
class SymbolicSet(SymbolicType):
    """Symbolic set.
    Uses Z3 Set theory for set operations.
    """

    z3_set: z3.ArrayRef
    element_sort: z3.SortRef
    _name: str = field(default="")

    def __post_init__(self):
        if not self._name:
            self._name = fresh_name("set")

    @property
    def type_tag(self) -> TypeTag:
        return TypeTag.SET

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_set

    def is_truthy(self) -> z3.BoolRef:
        if not hasattr(self, "_cached_truthy"):
            self._cached_truthy: z3.BoolRef = z3.Bool(fresh_name(f"set_nonempty_{self._name}"))
        return self._cached_truthy

    def is_falsy(self) -> z3.BoolRef:
        return z3.Not(self.is_truthy())

    @property
    def length(self) -> SymbolicInt:
        """Return symbolic cardinality (approximation)."""
        if not hasattr(self, "_cached_length"):
            self._cached_length: SymbolicInt = SymbolicInt(
                z3.Int(fresh_name(f"set_len_{self._name}"))
            )
        return self._cached_length

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        if isinstance(other, SymbolicSet):
            return self.z3_set == other.z3_set
        return z3.BoolVal(False)

    def contains(self, elem: SymbolicInt) -> SymbolicBool:
        """Check set membership."""
        return SymbolicBool(z3.IsMember(elem.z3_int, self.z3_set))

    def add(self, elem: SymbolicInt) -> SymbolicSet:
        """Return new set with element added."""
        return SymbolicSet(z3.SetAdd(self.z3_set, elem.z3_int), self.element_sort)

    def remove(self, elem: SymbolicInt) -> SymbolicSet:
        """Return new set with element removed."""
        return SymbolicSet(z3.SetDel(self.z3_set, elem.z3_int), self.element_sort)

    def union(self, other: SymbolicSet) -> SymbolicSet:
        """Set union."""
        return SymbolicSet(z3.SetUnion(self.z3_set, other.z3_set), self.element_sort)

    def intersection(self, other: SymbolicSet) -> SymbolicSet:
        """Set intersection."""
        return SymbolicSet(z3.SetIntersect(self.z3_set, other.z3_set), self.element_sort)

    def difference(self, other: SymbolicSet) -> SymbolicSet:
        """Set difference."""
        return SymbolicSet(z3.SetDifference(self.z3_set, other.z3_set), self.element_sort)

    def issubset(self, other: SymbolicSet) -> SymbolicBool:
        """Check if this is a subset of other."""
        return SymbolicBool(z3.IsSubset(self.z3_set, other.z3_set))

    @staticmethod
    def symbolic_int_set(name: str | None = None) -> SymbolicSet:
        """Create a fresh symbolic set of integers."""
        name = name or fresh_name("set")
        return SymbolicSet(
            cast("z3.ArrayRef", z3.Const(name, z3.SetSort(z3.IntSort()))), z3.IntSort(), name
        )

    @staticmethod
    def empty_int_set() -> SymbolicSet:
        """Create an empty int set."""
        return SymbolicSet(z3.EmptySet(z3.IntSort()), z3.IntSort(), "set()")
