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

"""
Type kinds and type representations for pysymex's type inference.

Contains:
- TypeKind: Enumeration of all Python type categories
- PyType: Rich frozen dataclass representing Python types with generics,
  union types, literal values, nullability, and type algebra operations
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum, auto


class TypeKind(Enum):
    """Enumeration of Python type categories."""

    NONE = auto()
    BOOL = auto()
    INT = auto()
    FLOAT = auto()
    COMPLEX = auto()
    STR = auto()
    BYTES = auto()
    LIST = auto()
    TUPLE = auto()
    SET = auto()
    FROZENSET = auto()
    DICT = auto()
    DEFAULTDICT = auto()
    COUNTER = auto()
    ORDERED_DICT = auto()
    CHAIN_MAP = auto()
    SEQUENCE = auto()
    MAPPING = auto()
    ITERABLE = auto()
    DEQUE = auto()
    ITERATOR = auto()
    NUMBER = auto()
    RANGE = auto()
    TYPE = auto()
    FILE = auto()
    SLICE = auto()
    MEMORYVIEW = auto()
    BYTEARRAY = auto()
    CODE = auto()
    DICT_KEYS = auto()
    DICT_VALUES = auto()
    DICT_ITEMS = auto()
    OBJECT = auto()

    @classmethod
    def int_type(cls) -> PyType:
        return PyType.int_()

    @classmethod
    def str_type(cls) -> PyType:
        return PyType.str_()

    @classmethod
    def bool_type(cls) -> PyType:
        return PyType.bool_()

    @classmethod
    def float_type(cls) -> PyType:
        return PyType.float_()

    @classmethod
    def list_type(cls, element_type: PyType | None = None) -> PyType:
        return PyType.list_(element_type)

    @classmethod
    def dict_type(cls, key_type: PyType | None = None, value_type: PyType | None = None) -> PyType:
        return PyType.dict_(key_type, value_type)

    @classmethod
    def tuple_type(cls, *element_types: PyType) -> PyType:
        return PyType.tuple_(*element_types)

    @classmethod
    def set_type(cls, element_type: PyType | None = None) -> PyType:
        return PyType.set_(element_type)

    @classmethod
    def none_type(cls) -> PyType:
        return PyType.none()

    @classmethod
    def int_(cls) -> PyType:
        """Int."""
        return PyType(kind=cls.INT, name="int")

    @classmethod
    def str_(cls) -> PyType:
        """Str."""
        return PyType(kind=cls.STR, name="str")

    @classmethod
    def bool_(cls) -> PyType:
        """Bool."""
        return PyType(kind=cls.BOOL, name="bool")

    @classmethod
    def float_(cls) -> PyType:
        """Float."""
        return PyType(kind=cls.FLOAT, name="float")

    @classmethod
    def list_(cls, element_type: PyType | None = None) -> PyType:
        """List."""
        params = (element_type,) if element_type else ()
        return PyType(kind=cls.LIST, name="list", params=params)

    @classmethod
    def dict_(cls, key_type: PyType | None = None, value_type: PyType | None = None) -> PyType:
        """Dict."""
        params = ()
        if key_type and value_type:
            params = (key_type, value_type)
        return PyType(kind=cls.DICT, name="dict", params=params)

    @classmethod
    def tuple_(cls, *element_types: PyType) -> PyType:
        """Tuple."""
        return PyType(kind=cls.TUPLE, name="tuple", params=element_types)

    @classmethod
    def set_(cls, element_type: PyType | None = None) -> PyType:
        """Set."""
        params = (element_type,) if element_type else ()
        return PyType(kind=cls.SET, name="set", params=params)

    @classmethod
    def none(cls) -> PyType:
        return PyType(kind=cls.NONE, name="None")

    FUNCTION = auto()
    METHOD = auto()
    LAMBDA = auto()
    COROUTINE = auto()
    GENERATOR = auto()
    ASYNC_GENERATOR = auto()
    CLASS = auto()
    INSTANCE = auto()
    MODULE = auto()
    ANY = auto()
    UNION = auto()
    OPTIONAL = auto()
    LITERAL = auto()
    TYPE_VAR = auto()
    PROTOCOL = auto()
    CALLABLE = auto()
    UNKNOWN = auto()
    BOTTOM = auto()


@dataclass(frozen=True)
class PyType:
    """
    Represents a Python type in the analysis.
    This is a rich representation that captures:
    - The kind of type (int, str, list, etc.)
    - Generic parameters (List[int], Dict[str, Any], etc.)
    - Known attributes and methods
    - Value constraints (Literal types, enum values)
    - Nullability
    """

    kind: TypeKind
    name: str = ""
    params: tuple[PyType, ...] = ()
    literal_values: frozenset[object] = frozenset()
    class_name: str | None = None
    union_members: frozenset[PyType] = frozenset()
    attributes: Mapping[str, PyType] = field(default_factory=lambda: dict[str, "PyType"]())
    nullable: bool = False
    confidence: float = 1.0
    source: str = "inferred"
    length: int | None = None
    value_constraints: frozenset[str] = frozenset()
    known_keys: frozenset[object] = frozenset()

    def __hash__(self) -> int:
        """Return the hash value of the object."""
        return hash(
            (
                self.kind,
                self.name,
                self.params,
                self.literal_values,
                self.class_name,
                self.nullable,
                self.length,
                self.value_constraints,
                self.known_keys,
                self.union_members,
            )
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PyType):
            return False
        return (
            self.kind == other.kind
            and self.name == other.name
            and self.params == other.params
            and self.literal_values == other.literal_values
            and self.class_name == other.class_name
            and self.nullable == other.nullable
            and self.length == other.length
            and self.value_constraints == other.value_constraints
            and self.known_keys == other.known_keys
            and self.union_members == other.union_members
        )

    @classmethod
    def none(cls) -> PyType:
        """Create None type."""
        return cls(kind=TypeKind.NONE, name="None")

    @classmethod
    def none_type(cls) -> PyType:
        """Create None type (alias for none())."""
        return cls.none()

    @classmethod
    def bool_(cls) -> PyType:
        """Create bool type."""
        return cls(kind=TypeKind.BOOL, name="bool")

    @classmethod
    def int_(cls) -> PyType:
        """Create int type."""
        return cls(kind=TypeKind.INT, name="int")

    @classmethod
    def float_(cls) -> PyType:
        """Create float type."""
        return cls(kind=TypeKind.FLOAT, name="float")

    @classmethod
    def str_(cls) -> PyType:
        """Create str type."""
        return cls(kind=TypeKind.STR, name="str")

    @classmethod
    def bytes_(cls) -> PyType:
        """Create bytes type."""
        return cls(kind=TypeKind.BYTES, name="bytes")

    @classmethod
    def list_(cls, element_type: PyType | None = None) -> PyType:
        """Create list type with optional element type."""
        params = (element_type,) if element_type else ()
        return cls(kind=TypeKind.LIST, name="list", params=params)

    @classmethod
    def dict_(
        cls,
        key_type: PyType | None = None,
        value_type: PyType | None = None,
    ) -> PyType:
        """Create dict type with optional key/value types."""
        params = ()
        if key_type and value_type:
            params = (key_type, value_type)
        return cls(kind=TypeKind.DICT, name="dict", params=params)

    @classmethod
    def defaultdict_(
        cls,
        key_type: PyType | None = None,
        value_type: PyType | None = None,
    ) -> PyType:
        """Create defaultdict type."""
        params = ()
        if key_type and value_type:
            params = (key_type, value_type)
        return cls(kind=TypeKind.DEFAULTDICT, name="defaultdict", params=params)

    @classmethod
    def set_(cls, element_type: PyType | None = None) -> PyType:
        """Create set type with optional element type."""
        params = (element_type,) if element_type else ()
        return cls(kind=TypeKind.SET, name="set", params=params)

    @classmethod
    def tuple_(cls, *element_types: PyType) -> PyType:
        """Create tuple type with element types."""
        return cls(kind=TypeKind.TUPLE, name="tuple", params=element_types)

    @classmethod
    def deque_(cls, element_type: PyType | None = None) -> PyType:
        """Create deque type with optional element type."""
        params = (element_type,) if element_type else ()
        return cls(kind=TypeKind.DEQUE, name="deque", params=params)

    @classmethod
    def union_(cls, *types: PyType) -> PyType:
        """Create union type."""
        members: set[PyType] = set()
        for t in types:
            if t.kind == TypeKind.UNION:
                members.update(t.union_members)
            else:
                members.add(t)
        if len(members) == 1:
            return members.pop()
        return cls(
            kind=TypeKind.UNION,
            name="Union",
            union_members=frozenset(members),
        )

    @classmethod
    def optional_(cls, inner_type: PyType) -> PyType:
        """Create Optional type (Union with None)."""
        return cls.union_(inner_type, cls.none())

    @classmethod
    def literal_(cls, *values: object) -> PyType:
        """Create Literal type with specific values."""
        return cls(
            kind=TypeKind.LITERAL,
            name="Literal",
            literal_values=frozenset(values),
        )

    @classmethod
    def any_(cls) -> PyType:
        """Create Any type."""
        return cls(kind=TypeKind.ANY, name="Any")

    @classmethod
    def unknown(cls) -> PyType:
        """Create unknown type."""
        return cls(kind=TypeKind.UNKNOWN, name="?")

    @classmethod
    def bottom(cls) -> PyType:
        """Create bottom type (empty/unreachable)."""
        return cls(kind=TypeKind.BOTTOM, name="⊥")

    @classmethod
    def bytes_type(cls) -> PyType:
        """Create bytes type (alias for bytes_)."""
        return cls.bytes_()

    def is_optional(self) -> bool:
        """Check if this type is Optional (NONE or Union containing None)."""
        if self.kind == TypeKind.NONE:
            return True
        if self.nullable:
            return True
        if self.kind == TypeKind.UNION:
            return any(m.kind == TypeKind.NONE for m in self.union_members)
        return False

    @classmethod
    def instance(cls, class_name: str, **attributes: PyType) -> PyType:
        """Create instance type for a class."""
        return cls(
            kind=TypeKind.INSTANCE,
            name=class_name,
            class_name=class_name,
            attributes=attributes,
        )

    @classmethod
    def callable_(
        cls,
        params: Sequence[PyType] = (),
        return_type: PyType | None = None,
    ) -> PyType:
        """Create Callable type."""
        ret = return_type or cls.any_()
        return cls(
            kind=TypeKind.CALLABLE,
            name="Callable",
            params=(*tuple(params), ret),
        )

    int_type = int_
    str_type = str_
    bool_type = bool_
    float_type = float_
    list_type = list_
    dict_type = dict_
    tuple_type = tuple_
    set_type = set_

    def is_numeric(self) -> bool:
        """Check if this is a numeric type."""
        return self.kind in {TypeKind.INT, TypeKind.FLOAT, TypeKind.COMPLEX}

    def is_collection(self) -> bool:
        """Check if this is a collection type."""
        return self.kind in {
            TypeKind.LIST,
            TypeKind.TUPLE,
            TypeKind.SET,
            TypeKind.FROZENSET,
            TypeKind.DICT,
            TypeKind.DEFAULTDICT,
            TypeKind.DEQUE,
        }

    def is_mapping(self) -> bool:
        """Check if this is a mapping type."""
        return self.kind in {TypeKind.DICT, TypeKind.DEFAULTDICT}

    def is_sequence(self) -> bool:
        """Check if this is a sequence type."""
        return self.kind in {TypeKind.LIST, TypeKind.TUPLE, TypeKind.DEQUE, TypeKind.STR}

    def is_subscriptable(self) -> bool:
        """Check if this type supports subscript operations."""
        return self.kind in {
            TypeKind.LIST,
            TypeKind.TUPLE,
            TypeKind.DICT,
            TypeKind.DEFAULTDICT,
            TypeKind.STR,
            TypeKind.BYTES,
            TypeKind.DEQUE,
        }

    def is_nullable(self) -> bool:
        """Check if this type can be None."""
        if self.kind == TypeKind.NONE:
            return True
        if self.nullable:
            return True
        if self.kind == TypeKind.UNION:
            return any(m.kind == TypeKind.NONE for m in self.union_members)
        return False

    def is_definitely_not_none(self) -> bool:
        """Check if this type definitely cannot be None."""
        if self.kind == TypeKind.NONE:
            return False
        if self.nullable:
            return False
        if self.kind == TypeKind.UNION:
            return not any(m.kind == TypeKind.NONE for m in self.union_members)
        return True

    def get_element_type(self) -> PyType:
        """Get element type for collections."""
        if self.params and len(self.params) >= 1:
            return self.params[0]
        return PyType.any_()

    def get_key_type(self) -> PyType:
        """Get key type for mappings."""
        if self.params and len(self.params) >= 1:
            return self.params[0]
        return PyType.any_()

    def get_value_type(self) -> PyType:
        """Get value type for mappings."""
        if self.params and len(self.params) >= 2:
            return self.params[1]
        return PyType.any_()

    def get_return_type(self) -> PyType:
        """Get return type for callables."""
        if self.kind == TypeKind.CALLABLE and self.params:
            return self.params[-1]
        return PyType.any_()

    def without_none(self) -> PyType:
        """Return this type with None removed from union."""
        if self.kind == TypeKind.NONE:
            return PyType.bottom()
        if self.kind == TypeKind.UNION:
            non_none = [m for m in self.union_members if m.kind != TypeKind.NONE]
            if not non_none:
                return PyType.bottom()
            if len(non_none) == 1:
                return non_none[0]
            return PyType.union_(*non_none)
        return self

    def join(self, other: PyType) -> PyType:
        """Compute least upper bound (join) of two types."""
        if self == other:
            return self
        if self.kind == TypeKind.BOTTOM:
            return other
        if other.kind == TypeKind.BOTTOM:
            return self
        if self.kind == TypeKind.ANY or other.kind == TypeKind.ANY:
            return PyType.any_()
        if self.kind == TypeKind.UNKNOWN or other.kind == TypeKind.UNKNOWN:
            return PyType.unknown()
        if self.kind == TypeKind.UNION or other.kind == TypeKind.UNION:
            members: set[PyType] = set()
            if self.kind == TypeKind.UNION:
                members.update(self.union_members)
            else:
                members.add(self)
            if other.kind == TypeKind.UNION:
                members.update(other.union_members)
            else:
                members.add(other)
            return PyType.union_(*members)
        if self.is_numeric() and other.is_numeric():
            if self.kind == TypeKind.COMPLEX or other.kind == TypeKind.COMPLEX:
                return PyType(kind=TypeKind.COMPLEX, name="complex")
            if self.kind == TypeKind.FLOAT or other.kind == TypeKind.FLOAT:
                return PyType.float_()
            return PyType.int_()
        if self.kind == other.kind and self.is_collection():
            if self.params and other.params:
                joined_params = tuple(
                    p1.join(p2) for p1, p2 in zip(self.params, other.params, strict=False)
                )
                return PyType(
                    kind=self.kind,
                    name=self.name,
                    params=joined_params,
                )
            return PyType(kind=self.kind, name=self.name)
        return PyType.union_(self, other)

    def meet(self, other: PyType) -> PyType:
        """Compute greatest lower bound (meet) of two types."""
        if self == other:
            return self
        if self.kind == TypeKind.ANY:
            return other
        if other.kind == TypeKind.ANY:
            return self
        if self.kind == TypeKind.BOTTOM or other.kind == TypeKind.BOTTOM:
            return PyType.bottom()
        if self.kind == TypeKind.UNION and other.kind == TypeKind.UNION:
            common = self.union_members & other.union_members
            if not common:
                return PyType.bottom()
            return PyType.union_(*common)
        if self.kind == TypeKind.UNION:
            if other in self.union_members:
                return other
            return PyType.bottom()
        if other.kind == TypeKind.UNION:
            if self in other.union_members:
                return self
            return PyType.bottom()
        return PyType.bottom()

    def is_subtype_of(self, other: PyType) -> bool:
        """Check if self is a subtype of other."""
        if self == other:
            return True
        if self.kind == TypeKind.BOTTOM:
            return True
        if other.kind == TypeKind.ANY:
            return True
        if self.kind == TypeKind.NONE and other.is_nullable():
            return True
        if self.kind == TypeKind.UNION:
            return all(m.is_subtype_of(other) for m in self.union_members)
        if other.kind == TypeKind.UNION:
            return any(self.is_subtype_of(m) for m in other.union_members)
        if self.is_numeric() and other.is_numeric():
            order = {TypeKind.INT: 0, TypeKind.FLOAT: 1, TypeKind.COMPLEX: 2}
            return order.get(self.kind, 99) <= order.get(other.kind, 99)

        if self.kind == TypeKind.BOOL and other.kind == TypeKind.INT:
            return True
        if self.kind == other.kind and self.params and other.params:
            if len(self.params) != len(other.params):
                return False
            return all(
                p1.is_subtype_of(p2) for p1, p2 in zip(self.params, other.params, strict=False)
            )
        return False

    def __repr__(self) -> str:
        """Repr."""
        if self.kind == TypeKind.UNION:
            members = " | ".join(repr(m) for m in sorted(self.union_members, key=str))
            return f"({members})"
        if self.kind == TypeKind.LITERAL:
            values = ", ".join(repr(v) for v in self.literal_values)
            return f"Literal[{values}]"
        if self.params:
            params = ", ".join(repr(p) for p in self.params)
            return f"{self.name}[{params}]"
        return self.name
