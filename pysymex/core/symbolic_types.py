"""Extended symbolic type system for pysymex.

This module provides a comprehensive type hierarchy that maps Python's dynamic
types to Z3's type system. Each type handles its own Z3 representation and
operations.

Type Hierarchy:
    SymbolicType (abstract base)
    +-- SymbolicPrimitive (abstract)
    |   +-- SymbolicInt        # Z3 Int
    |   +-- SymbolicBool       # Z3 Bool
    |   +-- SymbolicFloat      # Z3 Real
    |   +-- SymbolicNoneType   # Singleton
    |   +-- SymbolicString     # Z3 String
    +-- SymbolicCollection (abstract)
        +-- SymbolicTuple      # Fixed-length, heterogeneous
        +-- SymbolicList       # Variable-length, homogeneous
        +-- SymbolicDict       # Key-value mapping
        +-- SymbolicSet        # Unordered, unique elements

Implementation split across sub-modules for maintainability:
- symbolic_types_base: TypeTag, SymbolicType ABC, SymbolicNoneType
- symbolic_types_numeric: SymbolicBool, SymbolicInt, SymbolicFloat
- symbolic_types_containers: SymbolicString through SymbolicSet
- This file: coercion helpers, factory functions, re-exports
"""

from __future__ import annotations


from typing import Any, cast


import z3


from .symbolic_types_base import (
    SYMBOLIC_NONE,
    SymbolicNoneType,
    SymbolicType,
    TypeTag,
    fresh_name,
    reset_counters,
)


from .symbolic_types_numeric import (
    SymbolicBool,
    SymbolicFloat,
    SymbolicInt,
)


from .symbolic_types_containers import (
    SymbolicBytes,
    SymbolicDict,
    SymbolicList,
    SymbolicSet,
    SymbolicString,
    SymbolicTuple,
)


def coerce_to_bool(value: SymbolicType) -> SymbolicBool:
    """Convert any symbolic type to boolean."""

    if isinstance(value, SymbolicBool):
        return value

    return SymbolicBool(value.is_truthy())


def coerce_to_int(value: SymbolicType) -> SymbolicInt:
    """Convert symbolic type to int where possible."""

    if isinstance(value, SymbolicInt):
        return value

    elif isinstance(value, SymbolicBool):
        return SymbolicInt(z3.If(value.z3_bool, z3.IntVal(1), z3.IntVal(0)))

    elif isinstance(value, SymbolicFloat):
        return value.to_int()

    else:
        return SymbolicInt.symbolic(f"int_{value.name}")


def coerce_to_float(value: SymbolicType) -> SymbolicFloat:
    """Convert symbolic type to float where possible."""

    if isinstance(value, SymbolicFloat):
        return value

    elif isinstance(value, SymbolicInt):
        return SymbolicFloat(z3.ToReal(value.z3_int))

    elif isinstance(value, SymbolicBool):
        return SymbolicFloat(z3.If(value.z3_bool, z3.RealVal(1), z3.RealVal(0)))

    else:
        return SymbolicFloat.symbolic(f"float_{value.name}")


def coerce_to_string(value: SymbolicType) -> SymbolicString:
    """Convert symbolic type to string where possible."""

    if isinstance(value, SymbolicString):
        return value

    elif isinstance(value, SymbolicInt):
        return SymbolicString(z3.IntToStr(value.z3_int))

    else:
        return SymbolicString.symbolic(f"str_{value.name}")


def symbolic_from_python(value: Any) -> SymbolicType:
    """Create a symbolic value from a Python value."""

    if value is None:
        return SYMBOLIC_NONE

    elif isinstance(value, bool):
        return SymbolicBool.concrete(value)

    elif isinstance(value, int):
        return SymbolicInt.concrete(value)

    elif isinstance(value, float):
        return SymbolicFloat.concrete(value)

    elif isinstance(value, str):
        return SymbolicString.concrete(value)

    elif isinstance(value, bytes):
        return SymbolicBytes.concrete(value)

    elif isinstance(value, tuple):
        elements = tuple(symbolic_from_python(e) for e in cast("tuple[Any, ...]", value))

        return SymbolicTuple(elements)

    elif isinstance(value, list):
        if not value:
            return SymbolicList.concrete_int_list([])

        list_val = cast("list[Any]", value)

        if all(isinstance(e, int) for e in list_val):
            return SymbolicList.concrete_int_list(cast("list[int]", list_val))

        return SymbolicList.symbolic_int_list()

    elif isinstance(value, dict):
        return SymbolicDict.symbolic_int_dict()

    elif isinstance(value, set):
        return SymbolicSet.symbolic_int_set()

    else:
        return SymbolicInt.symbolic(f"unknown_{type(value).__name__}")


def symbolic_for_type(type_hint: type, name: str | None = None) -> SymbolicType:
    """Create a fresh symbolic value for a type hint."""

    if type_hint is type(None):
        return SYMBOLIC_NONE

    elif type_hint is bool:
        return SymbolicBool.symbolic(name)

    elif type_hint is int:
        return SymbolicInt.symbolic(name)

    elif type_hint is float:
        return SymbolicFloat.symbolic(name)

    elif type_hint is str:
        return SymbolicString.symbolic(name)

    elif type_hint is bytes:
        return SymbolicBytes.symbolic(name)

    elif type_hint is list:
        return SymbolicList.symbolic_int_list(name)

    elif type_hint is dict:
        return SymbolicDict.symbolic_int_dict(name)

    elif type_hint is set:
        return SymbolicSet.symbolic_int_set(name)

    else:
        return SymbolicInt.symbolic(name)


def is_numeric(value: SymbolicType) -> bool:
    """Check if value is numeric (int or float)."""

    return isinstance(value, (SymbolicInt, SymbolicFloat))


def is_sequence(value: SymbolicType) -> bool:
    """Check if value is a sequence type."""

    return isinstance(value, (SymbolicString, SymbolicBytes, SymbolicTuple, SymbolicList))


def is_collection(value: SymbolicType) -> bool:
    """Check if value is any collection type."""

    return isinstance(value, (SymbolicTuple, SymbolicList, SymbolicDict, SymbolicSet))


def get_common_type(a: SymbolicType, b: SymbolicType) -> TypeTag:
    """Get the common type for binary operations."""

    if isinstance(a, SymbolicFloat) or isinstance(b, SymbolicFloat):
        return TypeTag.FLOAT

    if isinstance(a, SymbolicInt) or isinstance(b, SymbolicInt):
        return TypeTag.INT

    if isinstance(a, SymbolicBool) and isinstance(b, SymbolicBool):
        return TypeTag.BOOL

    return TypeTag.UNKNOWN


__all__ = [
    "TypeTag",
    "SymbolicType",
    "SymbolicNoneType",
    "SYMBOLIC_NONE",
    "fresh_name",
    "reset_counters",
    "SymbolicBool",
    "SymbolicInt",
    "SymbolicFloat",
    "SymbolicString",
    "SymbolicBytes",
    "SymbolicTuple",
    "SymbolicList",
    "SymbolicDict",
    "SymbolicSet",
    "coerce_to_bool",
    "coerce_to_int",
    "coerce_to_float",
    "coerce_to_string",
    "symbolic_from_python",
    "symbolic_for_type",
    "is_numeric",
    "is_sequence",
    "is_collection",
    "get_common_type",
]
