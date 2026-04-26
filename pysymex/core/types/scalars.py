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

"""Core symbolic types for pysymex.
This module defines the symbolic type system that bridges Python's dynamic
typing with Z3's static typing. Each Python value is represented as a
union of possible Z3 types with type discriminators.
"""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypeGuard

import z3


if TYPE_CHECKING:
    from typing import Union

    from pysymex.core.types.containers import (
        SymbolicDict,
        SymbolicList,
        SymbolicObject,
    )

    AnySymbolic = Union[
        "SymbolicValue",
        "SymbolicNone",
        "SymbolicString",
        "SymbolicList",
        "SymbolicDict",
        "SymbolicObject",
    ]
else:
    AnySymbolic = object


_FROM_CONST_CACHE_LOCK = threading.Lock()


Z3_TRUE: z3.BoolRef = z3.BoolVal(True)
Z3_FALSE: z3.BoolRef = z3.BoolVal(False)
Z3_ZERO: z3.ArithRef = z3.IntVal(0)


_BV_WIDTH: int = 64
_Z3_OP_BV2INT: int = int(getattr(z3, "Z3_OP_BV2INT", -1))
_Z3_OP_BXOR: int = int(getattr(z3, "Z3_OP_BXOR", -1))


def _is_list_of_objects(value: object) -> TypeGuard[list[object]]:
    """Type guard to narrow a value to list[object]."""
    return isinstance(value, list)


def _is_dict_of_objects(value: object) -> TypeGuard[dict[object, object]]:
    """Type guard to narrow a value to dict[object, object]."""
    return isinstance(value, dict)


def _int_to_bv(expr: z3.ArithRef) -> z3.BitVecRef:
    """Convert a Z3 integer expression to a 64-bit bitvector."""
    try:
        if expr.decl().kind() == _Z3_OP_BV2INT and expr.num_args() == 1:
            underlying_bv = expr.arg(0)
            if z3.is_bv(underlying_bv):
                width = underlying_bv.size()
                if width == _BV_WIDTH:
                    return underlying_bv
                if width < _BV_WIDTH:
                    return z3.SignExt(_BV_WIDTH - width, underlying_bv)
                return z3.Extract(_BV_WIDTH - 1, 0, underlying_bv)
    except (AttributeError, z3.Z3Exception):
        pass
    return z3.Int2BV(expr, _BV_WIDTH)


def _bv_to_int(expr: z3.ExprRef) -> z3.ArithRef:
    """Convert a Z3 bitvector back to a (signed) integer."""
    if not z3.is_bv(expr):
        raise TypeError("Expected BitVecRef expression")
    return z3.BV2Int(expr, is_signed=True)


FROM_CONST_CACHE: dict[str | tuple[str, int], SymbolicValue] = {}
FROM_CONST_CACHE_LIMIT: int = 512


SYMBOLIC_CACHE: dict[str, tuple[SymbolicValue, z3.BoolRef]] = {}
SYMBOLIC_CACHE_LIMIT: int = 1024


int_to_bv = _int_to_bv
bv_to_int = _bv_to_int
BV_WIDTH: int = _BV_WIDTH


def _next_address() -> int:
    """Resolve the shared address counter lazily to avoid import cycles."""
    from pysymex.core.memory.addressing import next_address

    return next_address()


def fresh_name(prefix: str) -> str:
    """Generate a unique symbolic variable name.

    Delegates to :func:`pysymex.core.memory.addressing.next_address` which uses a
    ``contextvars.ContextVar`` counter, giving each async session its own
    isolated namespace and eliminating cross-session Z3 variable collisions.
    """
    return f"{prefix}_{_next_address()}"


def _guarded_nonzero_divisor(divisor: z3.ArithRef) -> z3.ArithRef:
    """Keep Z3 arithmetic defined when the divisor is symbolic.

    Concrete zero divisors should be handled by the caller so Python-visible
    zero division still raises eagerly where possible.
    """
    return z3.If(divisor == 0, z3.IntVal(1), divisor)


def _py_floor_div(a: z3.ArithRef, b: z3.ArithRef) -> z3.ArithRef:
    """Python-compatible floor division for Z3 integers.

    Python's ``//`` rounds toward negative infinity.  Z3's integer ``/``
    uses Euclidean division (remainder always >= 0), which matches Python
    when ``b > 0`` but differs by 1 when ``b < 0`` and the remainder is
    non-zero.  Correct by subtracting 1 in that case.
    """
    return z3.If(
        b > 0,
        a / b,
        z3.If(a % b == 0, a / b, a / b - 1),
    )


def _py_mod(a: z3.ArithRef, b: z3.ArithRef) -> z3.ArithRef:
    """Python-compatible modulo for Z3 integers."""
    q = _py_floor_div(a, b)
    return a - (b * q)


class SymbolicType(ABC):
    """Abstract base class for the pysymex symbolic type system.

    Defines the interface for bridge types that translate between Python's
    dynamic, late-bound objects and Z3's static, strongly-typed SMT
    expressions.

    **Core Design Principle:**
    Every symbolic value in the engine must be able to express its
    potential truthiness/falsiness as a Z3 boolean expression to allow
    the Explorer to make branch-splitting decisions based on solver SAT results.
    """

    __slots__ = ()

    @property
    @abstractmethod
    def name(self) -> str:
        """A stable debugging name for the symbolic expression."""

    @abstractmethod
    def to_z3(self) -> z3.ExprRef:
        """The primary Z3 expression representation of this value."""

    @abstractmethod
    def could_be_truthy(self) -> z3.BoolRef:
        """Z3 expression for when the Python value would be considered True."""

    @abstractmethod
    def could_be_falsy(self) -> z3.BoolRef:
        """Z3 expression for when the Python value would be considered False."""

    @abstractmethod
    def hash_value(self) -> int:
        """Stable, order-independent hash based on Z3 symbolic content."""


@dataclass(slots=True)
class SymbolicNone(SymbolicType):
    """Symbolic representation of Python ``None``.

    Always falsy, always ``is_none``.  Merging with another value
    produces a :class:`SymbolicValue` with an ``is_none`` discriminator.
    """

    _name: str = "None"
    _h_active: bool = field(default=False)

    def __post_init__(self) -> None:
        if self._name:
            if len(self._name) > 256:
                self._name = self._name[:128] + "..." + self._name[-125:]
            ln = self._name.lower()
            if ln in ("self", "cls") or ln.startswith(("self_", "cls_")):
                object.__setattr__(self, "_h_active", True)

    @property
    def name(self) -> str:
        return "None"

    @property
    def type_tag(self) -> str:
        return "NoneType"

    def to_z3(self) -> z3.ExprRef:
        return Z3_FALSE

    def could_be_truthy(self) -> z3.BoolRef:
        return Z3_FALSE

    def could_be_falsy(self) -> z3.BoolRef:
        return Z3_TRUE

    def hash_value(self) -> int:
        return hash("SymbolicNone")

    def conditional_merge(self, other: AnySymbolic, condition: z3.BoolRef) -> AnySymbolic:
        """Merge with another value based on a condition."""
        if isinstance(other, SymbolicNone):
            return self
        return SymbolicValue.from_specialized(self).conditional_merge(other, condition)

    def __repr__(self) -> str:
        return "SymbolicNone()"


def is_concrete_val(v: object) -> bool:
    if isinstance(v, (SymbolicValue, SymbolicString)):
        return getattr(v, "_constant_value", None) is not None
    return True


@dataclass(slots=True)
class SymbolicValue(SymbolicType):
    """An optimized 'any' type representing a union of potential Python values.

    **Encoding Strategy:**
    pysymex represents dynamic types as a collection of Z3 expressions with
    associated boolean 'discriminators' (e.g., `is_int`, `is_bool`). Only one
    discriminator is True in any given satisfying model, allowing the engine
    to model type-polymorphic operations (like `+`) as multiplexed Z3
    Condition-Action trees.

    **Optimization: Memory Cache Locality**
    Fields are declared such that the most frequently accessed Z3 references
    (`z3_int`, `is_int`, `z3_bool`, `is_bool`) are adjacent in the object's
    memory slot layout. This maximizes L1 cache hits during the high-frequency
    branch-evaluation loops of the symbolic explorer.

    Attributes:
        z3_int: Underlying Z3 Int expression used for numeric logic.
        is_int: Discriminator: True if this value represents a Python `int`.
        z3_bool: Underlying Z3 Bool expression used for boolean primitives.
        is_bool: Discriminator: True if this value represents a Python `bool`.
        z3_str: Z3 Seq[Char] for symbolic string support.
        is_str: Discriminator: True if this value represents a Python `str`.
        is_none: Discriminator: True if this value represents `None`.
    """

    z3_int: z3.ArithRef
    is_int: z3.BoolRef
    z3_bool: z3.BoolRef
    is_bool: z3.BoolRef
    z3_float: z3.FPRef = field(default_factory=lambda: z3.FPVal(0.0, z3.Float64()))
    is_float: z3.BoolRef = field(default_factory=lambda: Z3_FALSE)
    z3_str: z3.SeqRef = field(default_factory=lambda: z3.StringVal(""))
    is_str: z3.BoolRef = field(default_factory=lambda: Z3_FALSE)
    z3_addr: z3.ArithRef = field(default_factory=lambda: Z3_ZERO)
    is_obj: z3.BoolRef = field(default_factory=lambda: Z3_FALSE)

    z3_array: z3.ArrayRef | None = field(default=None)
    is_list: z3.BoolRef = field(default_factory=lambda: Z3_FALSE)
    is_dict: z3.BoolRef = field(default_factory=lambda: Z3_FALSE)

    _name: str = ""
    is_path: z3.BoolRef = field(default_factory=lambda: Z3_FALSE)
    is_none: z3.BoolRef = field(default_factory=lambda: Z3_FALSE)
    _constant_value: object = field(default=None, compare=False, repr=False)
    _bv_cache: z3.BitVecRef | None = field(default=None, init=False, repr=False, compare=False)

    affinity_type: str = field(default="NoneType", compare=False)
    _h_active: bool = field(default=False)

    def __post_init__(self) -> None:
        if self._name:
            if len(self._name) > 256:
                self._name = self._name[:128] + "..." + self._name[-125:]
            ln = self._name.lower()
            if ln in ("self", "cls") or ln.startswith(("self_", "cls_")):
                object.__setattr__(self, "_h_active", True)

    min_val: int | float | None = field(default=None, compare=False)
    max_val: int | float | None = field(default=None, compare=False)

    @property
    def value(self) -> object:
        """Return the constant value of the symbolic value."""
        return self._constant_value

    _truthy_cache: z3.BoolRef | None = field(default=None, init=False, repr=False, compare=False)
    _falsy_cache: z3.BoolRef | None = field(default=None, init=False, repr=False, compare=False)

    model_name: str | None = field(default=None, init=False, repr=False, compare=False)
    _enhanced_object: object | None = field(default=None, init=False, repr=False, compare=False)
    _type: str | None = field(default=None, init=False, repr=False, compare=False)
    pattern: str | None = field(default=None, init=False, repr=False, compare=False)

    @property
    def name(self) -> str:
        """Return the name of the symbolic value."""
        return self._name

    @property
    def type_tag(self) -> str:
        """Return the type tag of the symbolic value."""
        if self._type:
            return self._type
        if self.affinity_type and self.affinity_type not in ("unknown", "NoneType"):
            return self.affinity_type
        if self.is_float == Z3_TRUE:
            return "float"
        if self.is_int == Z3_TRUE:
            return "int"
        if self.is_bool == Z3_TRUE:
            return "bool"
        if self.is_str == Z3_TRUE:
            return "str"
        return "object"

    def to_z3(self) -> z3.ExprRef:
        return self.z3_int

    @property
    def as_bv(self) -> z3.BitVecRef:
        """Return cached 64-bit BitVec form of this integer."""
        if self._bv_cache is None:
            self._bv_cache = _int_to_bv(self.z3_int)
        return self._bv_cache

    def hash_value(self) -> int:
        """Stable hash of all hot Z3 components."""
        h = self.z3_int.hash()
        h = (h * 31) ^ self.is_int.hash()
        h = (h * 31) ^ self.z3_bool.hash()
        h = (h * 31) ^ self.is_bool.hash()
        h = (h * 31) ^ self.is_none.hash()
        h = (h * 31) ^ self.z3_str.hash()
        h = (h * 31) ^ self.is_str.hash()
        h = (h * 31) ^ self.z3_addr.hash()
        h = (h * 31) ^ self.is_obj.hash()
        h = (h * 31) ^ self.is_path.hash()
        h = (h * 31) ^ self.is_list.hash()
        h = (h * 31) ^ self.is_dict.hash()
        h = (h * 31) ^ self.z3_float.hash()
        h = (h * 31) ^ self.is_float.hash()
        if self.z3_array is not None:
            h = (h * 31) ^ self.z3_array.hash()
        return h

    def __hash__(self) -> int:
        """Return a stable hash so SymbolicValue works in sets and as dict keys.

        CPython sets __hash__ = None for dataclasses that define __eq__ without
        __hash__, which makes instances unhashable and causes `if sv == other:`
        comparisons to always be truthy (non-None object is truthy). By
        explicitly delegating to hash_value() we restore both invariants.
        (Fixes BUG-003.)
        """
        return self.hash_value()

    def could_be_truthy(self) -> z3.BoolRef:
        """Return a Z3 boolean expression that is true if the symbolic value
        could be truthy with optimized type checking."""
        cached = self._truthy_cache
        if cached is not None:
            return cached

        self_affinity = self.affinity_type

        if self_affinity == "bool":
            result = self.z3_bool
        elif self_affinity == "int":
            result = self.z3_int != 0
        elif self_affinity == "float":
            result = z3.Not(z3.fpIsZero(self.z3_float))
        elif self_affinity == "str":
            result = z3.Length(self.z3_str) > 0
        elif self_affinity == "list":
            result = self.z3_int != 0
        elif self_affinity == "dict":
            result = self.z3_int != 0
        elif self_affinity == "path":
            result = Z3_TRUE
        elif self_affinity == "obj":
            result = Z3_TRUE
        elif self_affinity == "none":
            result = Z3_FALSE
        else:
            result = z3.Or(
                z3.And(self.is_bool, self.z3_bool),
                z3.And(self.is_int, self.z3_int != 0),
                z3.And(self.is_str, z3.Length(self.z3_str) > 0),
                z3.And(self.is_float, z3.Not(z3.fpIsZero(self.z3_float))),
                z3.And(self.is_list, self.z3_int != 0),
                z3.And(self.is_dict, self.z3_int != 0),
                self.is_path,
                self.is_obj,
            )

        self._truthy_cache = result
        return result

    def could_be_falsy(self) -> z3.BoolRef:
        """Return a Z3 boolean expression that is true if the symbolic value
        could be falsy with optimized type checking."""
        cached = self._falsy_cache
        if cached is not None:
            return cached

        self_affinity = self.affinity_type

        if self_affinity == "bool":
            result = z3.Not(self.z3_bool)
        elif self_affinity == "int":
            result = self.z3_int == 0
        elif self_affinity == "float":
            result = z3.fpIsZero(self.z3_float)
        elif self_affinity == "str":
            result = z3.Length(self.z3_str) == 0
        elif self_affinity == "list":
            result = self.z3_int == 0
        elif self_affinity == "dict":
            result = self.z3_int == 0
        elif self_affinity == "none":
            result = Z3_TRUE
        elif self_affinity == "path":
            result = Z3_FALSE
        elif self_affinity == "obj":
            result = Z3_FALSE
        else:
            result = z3.Or(
                z3.And(self.is_bool, z3.Not(self.z3_bool)),
                z3.And(self.is_int, self.z3_int == 0),
                z3.And(self.is_float, z3.fpIsZero(self.z3_float)),
                z3.And(self.is_str, z3.Length(self.z3_str) == 0),
                z3.And(self.is_list, self.z3_int == 0),
                z3.And(self.is_dict, self.z3_int == 0),
                self.is_none,
            )

        self._falsy_cache = result
        return result

    def conditional_merge(self, other: AnySymbolic, condition: z3.BoolRef) -> SymbolicValue:
        """Merge with another value based on a condition: If(condition, self, other).

        Optimized to only create z3.If() for fields that actually differ,
        reducing AST bloat from 15+ conditionals to only necessary ones.
        """
        if isinstance(other, SymbolicNone):
            merged = other.conditional_merge(self, z3.Not(condition))
            if isinstance(merged, SymbolicValue):
                return merged
            return SymbolicValue.from_const(merged)

        if not isinstance(other, SymbolicValue):
            other_sv = SymbolicValue.from_const(other)
        else:
            other_sv = other

        if self is other_sv:
            return self

        def merge_arith(self_val: z3.ArithRef, other_val: z3.ArithRef) -> z3.ArithRef:
            if z3.eq(self_val, other_val):
                return self_val
            return z3.If(condition, self_val, other_val)

        def merge_bool(self_val: z3.BoolRef, other_val: z3.BoolRef) -> z3.BoolRef:
            if z3.eq(self_val, other_val):
                return self_val
            return z3.If(condition, self_val, other_val)

        def merge_str(self_val: z3.SeqRef, other_val: z3.SeqRef) -> z3.SeqRef:
            if z3.eq(self_val, other_val):
                return self_val
            return z3.If(condition, self_val, other_val)

        def merge_float(self_val: z3.FPRef, other_val: z3.FPRef) -> z3.FPRef:
            if z3.eq(self_val, other_val):
                return self_val
            return z3.If(condition, self_val, other_val)

        merged_array: z3.ArrayRef | None = None
        if self.z3_array is not None and other_sv.z3_array is not None:
            if z3.eq(self.z3_array, other_sv.z3_array):
                merged_array = self.z3_array
            else:
                array_expr = z3.If(condition, self.z3_array, other_sv.z3_array)
                merged_array = array_expr
        elif self.z3_array is not None:
            merged_array = self.z3_array
        elif other_sv.z3_array is not None:
            merged_array = other_sv.z3_array

        return SymbolicValue(
            _name=f"If({condition}, {self._name}, {other_sv.name})",
            _h_active=self._h_active or other_sv._h_active,
            z3_int=merge_arith(self.z3_int, other_sv.z3_int),
            is_int=merge_bool(self.is_int, other_sv.is_int),
            z3_bool=merge_bool(self.z3_bool, other_sv.z3_bool),
            is_bool=merge_bool(self.is_bool, other_sv.is_bool),
            z3_str=merge_str(self.z3_str, other_sv.z3_str),
            is_str=merge_bool(self.is_str, other_sv.is_str),
            z3_addr=merge_arith(self.z3_addr, other_sv.z3_addr),
            is_obj=merge_bool(self.is_obj, other_sv.is_obj),
            is_path=merge_bool(self.is_path, other_sv.is_path),
            is_none=merge_bool(self.is_none, other_sv.is_none),
            z3_float=merge_float(self.z3_float, other_sv.z3_float),
            is_float=merge_bool(self.is_float, other_sv.is_float),
            is_list=merge_bool(self.is_list, other_sv.is_list),
            is_dict=merge_bool(self.is_dict, other_sv.is_dict),
            z3_array=merged_array,
        )

    def as_string(self) -> SymbolicString:
        """Downcast this unified value back to a SymbolicString."""
        from pysymex.core.types.scalars import SymbolicString

        return SymbolicString(
            _z3_str=self.z3_str,
            _z3_len=z3.Length(self.z3_str),
            _name=self._name,
            _unified=self,
        )

    @staticmethod
    def symbolic(name: str) -> tuple[SymbolicValue, z3.BoolRef]:
        """Create a fresh symbolic value with type constraint."""
        id_suffix = _next_address()
        z3_int = z3.Int(f"{name}_{id_suffix}_int")
        z3_bool = z3.Bool(f"{name}_{id_suffix}_bool")
        z3_str = z3.String(f"{name}_{id_suffix}_str")
        z3_addr = z3.Int(f"{name}_{id_suffix}_addr")
        z3_float = z3.FP(f"{name}_{id_suffix}_float", z3.Float64())
        is_int = z3.Bool(f"{name}_{id_suffix}_is_int")
        is_bool = z3.Bool(f"{name}_{id_suffix}_is_bool")
        is_str = z3.Bool(f"{name}_{id_suffix}_is_str")
        is_path = z3.Bool(f"{name}_{id_suffix}_is_path")
        is_obj = z3.Bool(f"{name}_{id_suffix}_is_obj")
        is_none = z3.Bool(f"{name}_{id_suffix}_is_none")
        is_float = z3.Bool(f"{name}_{id_suffix}_is_float")
        is_list = z3.Bool(f"{name}_{id_suffix}_is_list")
        is_dict = z3.Bool(f"{name}_{id_suffix}_is_dict")

        type_vars = [is_int, is_bool, is_str, is_path, is_obj, is_none, is_float, is_list, is_dict]
        type_constraint = z3.Or(*type_vars)

        result = (
            SymbolicValue(
                z3_int=z3_int,
                is_int=is_int,
                z3_bool=z3_bool,
                is_bool=is_bool,
                z3_str=z3_str,
                is_str=is_str,
                z3_addr=z3_addr,
                is_obj=is_obj,
                is_path=is_path,
                is_none=is_none,
                z3_float=z3_float,
                is_float=is_float,
                is_list=is_list,
                is_dict=is_dict,
                _name=name,
            ),
            type_constraint,
        )
        return result

    @staticmethod
    def symbolic_int(name: str) -> tuple[SymbolicValue, z3.BoolRef]:
        """Create a specialized symbolic integer (more efficient for solver)."""
        z3_int = z3.Int(f"{name}_int")
        sv = SymbolicValue(
            _name=name,
            z3_int=z3_int,
            is_int=Z3_TRUE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_path=Z3_FALSE,
            affinity_type="int",
        )
        if name.lower().startswith(("self", "cls")):
            object.__setattr__(sv, "_h_active", True)
        return sv, Z3_TRUE

    @staticmethod
    def symbolic_bool(name: str) -> tuple[SymbolicValue, z3.BoolRef]:
        """Create a specialized symbolic boolean (more efficient for solver)."""
        z3_bool = z3.Bool(f"{name}_bool")
        sv = SymbolicValue(
            _name=name,
            z3_int=z3.If(z3_bool, z3.IntVal(1), Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=z3_bool,
            is_bool=Z3_TRUE,
            is_path=Z3_FALSE,
            affinity_type="bool",
        )
        if name.lower().startswith(("self", "cls")):
            object.__setattr__(sv, "_h_active", True)
        return sv, Z3_TRUE

    @staticmethod
    def from_specialized(value: object) -> SymbolicValue:
        """Convert a specialized SymbolicType to a unified SymbolicValue with optimized affinity_type."""
        from pysymex.core.types.numeric import SymbolicBool, SymbolicInt, SymbolicFloat
        from pysymex.core.types.containers import SymbolicList, SymbolicDict, SymbolicObject
        from pysymex.core.types.symbolic_containers import (
            SymbolicString,
            SymbolicBytes,
            SymbolicTuple,
            SymbolicSet,
        )
        from pysymex.core.types.base import SymbolicNoneType

        if isinstance(value, SymbolicValue):
            return value

        name = getattr(value, "name", str(value))

        if isinstance(value, SymbolicNoneType):
            return SymbolicValue(
                _name=name,
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_none=Z3_TRUE,
                is_path=Z3_FALSE,
                _h_active=getattr(value, "_h_active", False),
                affinity_type="none",
            )
        if isinstance(value, SymbolicBool):
            return SymbolicValue(
                _name=name,
                z3_int=z3.If(value.z3_bool, z3.IntVal(1), Z3_ZERO),
                is_int=Z3_FALSE,
                z3_bool=value.z3_bool,
                is_bool=Z3_TRUE,
                is_path=Z3_FALSE,
                affinity_type="bool",
            )
        if isinstance(value, SymbolicInt):
            return SymbolicValue(
                _name=name,
                z3_int=value.z3_int,
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_path=Z3_FALSE,
                affinity_type="int",
            )
        if isinstance(value, SymbolicFloat):
            _abs_floor = z3.ToInt(z3.If(value.z3_real >= 0, value.z3_real, -value.z3_real))
            _sign = z3.If(value.z3_real < 0, z3.IntVal(-1), z3.IntVal(1))
            return SymbolicValue(
                _name=name,
                z3_int=_abs_floor * _sign,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                z3_float=z3.fpToFP(z3.RNE(), value.z3_real, z3.Float64()),
                is_float=Z3_TRUE,
                is_path=Z3_FALSE,
                affinity_type="float",
            )
        if isinstance(value, SymbolicString):
            return SymbolicValue(
                _name=name,
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                z3_str=value.z3_str,
                is_str=Z3_TRUE,
                is_path=Z3_FALSE,
                affinity_type="str",
            )
        if isinstance(value, SymbolicList):
            z3_len = getattr(value, "z3_len", None)
            if z3_len is None and hasattr(value, "z3_seq"):
                z3_len = z3.Length(getattr(value, "z3_seq"))
            if z3_len is None:
                z3_len = Z3_ZERO
            return SymbolicValue(
                _name=name,
                z3_int=z3_len,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                z3_array=getattr(value, "z3_array", None),
                is_list=Z3_TRUE,
                is_path=Z3_FALSE,
                affinity_type="list",
            )
        if isinstance(value, SymbolicDict):
            z3_len = getattr(value, "z3_len", None)
            if z3_len is None and hasattr(value, "length"):
                len_obj = getattr(value, "length")
                z3_len = (
                    getattr(len_obj, "z3_int", Z3_ZERO)
                    if not isinstance(len_obj, (int, float))
                    else z3.IntVal(int(len_obj))
                )
            if z3_len is None:
                z3_len = Z3_ZERO
            return SymbolicValue(
                _name=name,
                z3_int=z3_len,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                z3_array=getattr(value, "z3_array", None),
                is_dict=Z3_TRUE,
                is_path=Z3_FALSE,
                affinity_type="dict",
            )
        if isinstance(value, SymbolicObject):
            return SymbolicValue(
                _name=name,
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                z3_addr=value.z3_addr,
                is_obj=Z3_TRUE,
                is_path=Z3_FALSE,
                _h_active=getattr(value, "_h_active", False),
                affinity_type="obj",
            )
        if isinstance(value, (SymbolicBytes, SymbolicTuple, SymbolicSet)):
            return SymbolicValue(
                _name=name,
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_path=Z3_FALSE,
                affinity_type="unknown",
            )

        if hasattr(value, "type_tag"):
            cls_name = type(value).__name__
            if cls_name == "SymbolicString":
                return SymbolicValue(
                    _name=name,
                    z3_int=Z3_ZERO,
                    is_int=Z3_FALSE,
                    z3_bool=Z3_FALSE,
                    is_bool=Z3_FALSE,
                    z3_str=getattr(value, "z3_str", z3.StringVal("")),
                    is_str=Z3_TRUE,
                    is_path=Z3_FALSE,
                    affinity_type="str",
                )
            if cls_name == "SymbolicList":
                return SymbolicValue(
                    _name=name,
                    z3_int=Z3_ZERO,
                    is_int=Z3_FALSE,
                    z3_bool=Z3_FALSE,
                    is_bool=Z3_FALSE,
                    z3_array=getattr(value, "z3_array", None),
                    is_list=Z3_TRUE,
                    is_path=Z3_FALSE,
                    affinity_type="list",
                )
            if cls_name == "SymbolicDict":
                return SymbolicValue(
                    _name=name,
                    z3_int=Z3_ZERO,
                    is_int=Z3_FALSE,
                    z3_bool=Z3_FALSE,
                    is_bool=Z3_FALSE,
                    z3_array=getattr(value, "z3_array", None),
                    is_dict=Z3_TRUE,
                    is_path=Z3_FALSE,
                    affinity_type="dict",
                )

            return SymbolicValue(
                _name=name,
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_path=Z3_FALSE,
                affinity_type="unknown",
            )

        return SymbolicValue.from_const(value)

    @staticmethod
    def from_const(value: object) -> SymbolicValue:
        """Create a concrete symbolic value from a Python constant.

        Caches None, True, False, and small integers to avoid repeated
        Z3 allocation.
        """
        if isinstance(value, SymbolicValue):
            return value
        if value is None:
            cached = FROM_CONST_CACHE.get("None")
            if cached is not None:
                return cached
            sv = SymbolicValue(
                _name="None",
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_TRUE,
                affinity_type="NoneType",
                _h_active=False,
            )
            with _FROM_CONST_CACHE_LOCK:
                FROM_CONST_CACHE["None"] = sv
            return sv
        if isinstance(value, bool):
            key = "True" if value else "False"
            cached = FROM_CONST_CACHE.get(key)
            if cached is not None:
                return cached

            if value:
                sv = SymbolicValue(
                    _name="True",
                    z3_int=z3.IntVal(1),
                    is_int=Z3_FALSE,
                    z3_bool=Z3_TRUE,
                    is_bool=Z3_TRUE,
                    is_path=Z3_FALSE,
                    _constant_value=True,
                    affinity_type="bool",
                    min_val=1,
                    max_val=1,
                )
            else:
                sv = SymbolicValue(
                    _name="False",
                    z3_int=Z3_ZERO,
                    is_int=Z3_FALSE,
                    z3_bool=Z3_FALSE,
                    is_bool=Z3_TRUE,
                    is_path=Z3_FALSE,
                    _constant_value=False,
                    affinity_type="bool",
                    min_val=0,
                    max_val=0,
                )

            with _FROM_CONST_CACHE_LOCK:
                FROM_CONST_CACHE[key] = sv
            return sv
        if isinstance(value, int):
            key = ("int", value)
            cached = FROM_CONST_CACHE.get(key)
            if cached is not None:
                return cached
            sv = SymbolicValue(
                _name=str(value),
                z3_int=z3.IntVal(value),
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                z3_float=z3.FPVal(float(value), z3.Float64()),
                is_float=Z3_FALSE,
                is_path=Z3_FALSE,
                _constant_value=value,
                affinity_type="int",
                min_val=value,
                max_val=value,
            )

            with _FROM_CONST_CACHE_LOCK:
                if len(FROM_CONST_CACHE) < FROM_CONST_CACHE_LIMIT:
                    FROM_CONST_CACHE[key] = sv
            return sv

        if isinstance(value, float):
            try:
                int_val = int(value)
                z3_int = z3.IntVal(int_val)
            except (ValueError, OverflowError):
                z3_int = Z3_ZERO

            sv = SymbolicValue(
                _name=str(value),
                z3_int=z3_int,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                z3_float=z3.FPVal(value, z3.Float64()),
                is_float=Z3_TRUE,
                is_path=Z3_FALSE,
                _constant_value=value,
                affinity_type="float",
                min_val=value,
                max_val=value,
            )
            return sv

        if hasattr(value, "type_tag"):
            return SymbolicValue.from_specialized(value)

        if isinstance(value, str):
            from pysymex.core.types.scalars import SymbolicString

            return SymbolicValue.from_specialized(SymbolicString.from_const(value))

        sv = SymbolicValue(
            _name=str(value),
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_path=Z3_FALSE,
            _constant_value=value,
        )
        if _is_list_of_objects(value):
            sv.is_list = Z3_TRUE
            sv.affinity_type = "list"
            sv.z3_int = z3.IntVal(len(value))
            sv._enhanced_object = value
            sv._constant_value = value
        elif _is_dict_of_objects(value):
            sv.is_dict = Z3_TRUE
            sv.affinity_type = "dict"
            sv.z3_int = z3.IntVal(len(value))
            sv._enhanced_object = value
            sv._constant_value = value
        elif isinstance(value, tuple):
            sv._enhanced_object = value
            sv._constant_value = value
        elif isinstance(value, set):
            sv._enhanced_object = value
            sv._constant_value = value
        else:
            sv._enhanced_object = value
        return sv

    @staticmethod
    def from_z3(expr: z3.ExprRef, name: str | None = None) -> SymbolicValue:
        """Create a SymbolicValue from a Z3 expression."""
        if name is None:
            name = str(expr)
        if isinstance(expr, z3.BoolRef):
            return SymbolicValue(
                _name=name,
                z3_int=z3.If(expr, z3.IntVal(1), Z3_ZERO),
                is_int=Z3_FALSE,
                z3_bool=expr,
                is_bool=Z3_TRUE,
                is_path=Z3_FALSE,
            )
        elif isinstance(expr, z3.ArithRef):
            return SymbolicValue(
                _name=name,
                z3_int=expr,
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_path=Z3_FALSE,
            )
        else:
            return SymbolicValue(
                _name=name,
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_path=Z3_FALSE,
            )

    @staticmethod
    def symbolic_path(name: str) -> tuple[SymbolicValue, z3.BoolRef]:
        """Create a fresh symbolic path."""
        val, constraint = SymbolicValue.symbolic(name)
        path_constraint = z3.And(constraint, val.is_path)

        if not val._h_active and name:
            if name.lower().startswith(("self", "cls")):
                object.__setattr__(val, "_h_active", True)

        return val, path_constraint

    def __add__(self, other: object) -> SymbolicValue:
        """Python addition operator with optimized type checking."""
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            return SymbolicValue(
                _name=f"({self._name}+{other._name})",
                z3_int=self.z3_int + other.z3_int,
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
            )

        if self_affinity == "bool" and other_affinity == "bool":
            return SymbolicValue(
                _name=f"({self._name}+{other._name})",
                z3_int=z3.If(self.z3_bool, z3.IntVal(1), Z3_ZERO)
                + z3.If(other.z3_bool, z3.IntVal(1), Z3_ZERO),
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
            )

        res_int = self.z3_int + other.z3_int
        is_int_like_self = z3.Or(self.is_int, self.is_bool)
        is_int_like_other = z3.Or(other.is_int, other.is_bool)
        is_int_res = z3.And(is_int_like_self, is_int_like_other)

        if z3.is_false(self.is_float) and z3.is_false(other.is_float):
            res_float = z3.FPVal(0.0, z3.Float64())
            is_float_res = Z3_FALSE
        else:
            left_fp = z3.If(
                self.is_float,
                self.z3_float,
                z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64()),
            )
            right_fp = z3.If(
                other.is_float,
                other.z3_float,
                z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64()),
            )
            res_float = z3.fpAdd(z3.RNE(), left_fp, right_fp)
            is_float_res = z3.Or(self.is_float, other.is_float)

        if z3.is_false(self.is_str) and z3.is_false(other.is_str):
            res_str = z3.StringVal("")
            is_str_res = Z3_FALSE
        else:
            res_str = z3.If(
                z3.And(self.is_str, other.is_str),
                z3.Concat(self.z3_str, other.z3_str),
                z3.StringVal(""),
            )
            is_str_res = z3.And(self.is_str, other.is_str)

        return SymbolicValue(
            _name=f"({self._name}+{other._name})",
            z3_int=res_int,
            is_int=is_int_res,
            z3_float=res_float,
            is_float=is_float_res,
            z3_str=res_str,
            is_str=is_str_res,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            z3_addr=Z3_ZERO,
            is_obj=Z3_FALSE,
            is_list=Z3_FALSE,
            is_dict=Z3_FALSE,
            is_path=Z3_FALSE,
            is_none=Z3_FALSE,
        )

    def __sub__(self, other: object) -> SymbolicValue:
        """Python subtraction operator with optimized type checking."""
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            return SymbolicValue(
                _name=f"({self._name}-{other._name})",
                z3_int=self.z3_int - other.z3_int,
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
            )

        res_int = self.z3_int - other.z3_int
        is_int_res = z3.And(z3.Or(self.is_int, self.is_bool), z3.Or(other.is_int, other.is_bool))

        if z3.is_false(self.is_float) and z3.is_false(other.is_float):
            res_float = z3.FPVal(0.0, z3.Float64())
            is_float_res = Z3_FALSE
        else:
            left_fp = z3.If(
                self.is_float,
                self.z3_float,
                z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64()),
            )
            right_fp = z3.If(
                other.is_float,
                other.z3_float,
                z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64()),
            )
            res_float = z3.fpSub(z3.RNE(), left_fp, right_fp)
            is_float_res = z3.Or(self.is_float, other.is_float)

        return SymbolicValue(
            _name=f"({self._name}-{other._name})",
            z3_int=res_int,
            is_int=is_int_res,
            z3_float=res_float,
            is_float=is_float_res,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            z3_addr=Z3_ZERO,
            is_obj=Z3_FALSE,
            is_list=Z3_FALSE,
            is_dict=Z3_FALSE,
            is_path=Z3_FALSE,
            is_none=Z3_FALSE,
        )

    def __mul__(self, other: object) -> SymbolicValue:
        """Python multiplication operator with optimized type checking."""
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            return SymbolicValue(
                _name=f"({self._name}*{other._name})",
                z3_int=self.z3_int * other.z3_int,
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
            )

        res_int = self.z3_int * other.z3_int
        is_int_res = z3.And(z3.Or(self.is_int, self.is_bool), z3.Or(other.is_int, other.is_bool))

        if z3.is_false(self.is_float) and z3.is_false(other.is_float):
            res_float = z3.FPVal(0.0, z3.Float64())
            is_float_res = Z3_FALSE
        else:
            left_fp = z3.If(
                self.is_float,
                self.z3_float,
                z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64()),
            )
            right_fp = z3.If(
                other.is_float,
                other.z3_float,
                z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64()),
            )
            res_float = z3.fpMul(z3.RNE(), left_fp, right_fp)
            is_float_res = z3.Or(self.is_float, other.is_float)

        return SymbolicValue(
            _name=f"({self._name}*{other._name})",
            z3_int=res_int,
            is_int=is_int_res,
            z3_float=res_float,
            is_float=is_float_res,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            z3_addr=Z3_ZERO,
            is_obj=Z3_FALSE,
            is_list=Z3_FALSE,
            is_dict=Z3_FALSE,
            is_path=Z3_FALSE,
            is_none=Z3_FALSE,
        )

    def __neg__(self) -> SymbolicValue:
        """Python negation operator with optimized type checking."""
        self_affinity = self.affinity_type

        if self_affinity == "int":
            return SymbolicValue(
                _name=f"(-{self._name})",
                z3_int=-self.z3_int,
                is_int=Z3_TRUE,
                z3_float=z3.FPVal(0.0, z3.Float64()),
                is_float=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                affinity_type="int",
            )

        if self_affinity == "float":
            return SymbolicValue(
                _name=f"(-{self._name})",
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_float=z3.fpNeg(self.z3_float),
                is_float=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                affinity_type="float",
            )

        return SymbolicValue(
            _name=f"(-{self._name})",
            z3_int=-self.z3_int,
            is_int=self.is_int,
            z3_float=z3.fpNeg(self.z3_float),
            is_float=self.is_float,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
        )

    def __mod__(self, other: object) -> SymbolicValue:
        """Python modulo operator with optimized type checking."""
        if is_concrete_val(self) and is_concrete_val(other):
            try:
                lhs_const = self._constant_value
                cv_other = getattr(other, "_constant_value", other)
                if (
                    isinstance(lhs_const, (int, float, bool))
                    and isinstance(cv_other, (int, float, bool))
                    and cv_other != 0
                ):
                    return SymbolicValue.from_const(lhs_const % cv_other)
            except (AttributeError, TypeError, ZeroDivisionError):
                pass
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            if z3.is_int_value(other.z3_int) and other.z3_int.as_long() == 0:
                raise ZeroDivisionError("division by zero")
            safe_divisor = _guarded_nonzero_divisor(other.z3_int)
            raw_res = _py_mod(self.z3_int, safe_divisor)
            cv = getattr(other, "_constant_value", None)
            guarded_res = (
                raw_res
                if (cv is not None and cv != 0)
                else z3.If(other.z3_int != 0, raw_res, Z3_ZERO)
            )
            return SymbolicValue(
                _name=f"({self._name}%{other._name})",
                z3_int=guarded_res,
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                z3_float=z3.FPVal(0.0, z3.Float64()),
                is_float=Z3_FALSE,
                affinity_type="int",
            )

        if z3.is_int_value(other.z3_int) and other.z3_int.as_long() == 0:
            raise ZeroDivisionError("division by zero")
        safe_divisor = _guarded_nonzero_divisor(other.z3_int)

        raw_res = _py_mod(self.z3_int, safe_divisor)
        cv = getattr(other, "_constant_value", None)
        if cv is not None and cv != 0:
            guarded_res = raw_res
        else:
            guarded_res = z3.If(other.z3_int != 0, raw_res, Z3_ZERO)

        if z3.is_false(self.is_float) and z3.is_false(other.is_float):
            guarded_fp_res = z3.FPVal(0.0, z3.Float64())
            is_float_res = Z3_FALSE
        else:
            left_fp = z3.If(
                self.is_float,
                self.z3_float,
                z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64()),
            )
            right_fp = z3.If(
                other.is_float,
                other.z3_float,
                z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64()),
            )

            safe_right_fp = z3.If(z3.fpIsZero(right_fp), z3.FPVal(1.0, z3.Float64()), right_fp)
            raw_fp_div = z3.fpDiv(z3.RNE(), left_fp, safe_right_fp)
            fp_floored = z3.fpRoundToIntegral(z3.RTN(), raw_fp_div)
            fp_mod_res = z3.fpSub(z3.RNE(), left_fp, z3.fpMul(z3.RNE(), fp_floored, safe_right_fp))
            guarded_fp_res = z3.If(
                z3.Not(z3.fpIsZero(right_fp)), fp_mod_res, z3.fpNaN(z3.Float64())
            )

            is_float_res = z3.And(
                z3.Or(self.is_float, other.is_float),
                z3.Or(self.is_int, self.is_bool, self.is_float),
                z3.Or(other.is_int, other.is_bool, other.is_float),
            )

        return SymbolicValue(
            _name=f"({self._name}%{other._name})",
            z3_int=guarded_res,
            is_int=z3.And(z3.Or(self.is_int, self.is_bool), z3.Or(other.is_int, other.is_bool)),
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            z3_float=guarded_fp_res,
            is_float=is_float_res,
            affinity_type="float",
        )

    def __floordiv__(self, other: object) -> SymbolicValue:
        """Python floor division operator with optimized type checking."""
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            if z3.is_int_value(other.z3_int) and other.z3_int.as_long() == 0:
                raise ZeroDivisionError("division by zero")
            safe_divisor = _guarded_nonzero_divisor(other.z3_int)
            raw_res = _py_floor_div(self.z3_int, safe_divisor)
            cv = getattr(other, "_constant_value", None)
            guarded_res = (
                raw_res
                if (cv is not None and cv != 0)
                else z3.If(other.z3_int != 0, raw_res, Z3_ZERO)
            )
            return SymbolicValue(
                _name=f"({self._name}//{other._name})",
                z3_int=guarded_res,
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                z3_float=z3.FPVal(0.0, z3.Float64()),
                is_float=Z3_FALSE,
                affinity_type="int",
            )

        if z3.is_int_value(other.z3_int) and other.z3_int.as_long() == 0:
            raise ZeroDivisionError("division by zero")
        safe_divisor = _guarded_nonzero_divisor(other.z3_int)

        raw_res = _py_floor_div(self.z3_int, safe_divisor)
        cv = getattr(other, "_constant_value", None)
        if cv is not None and cv != 0:
            guarded_res = raw_res
        else:
            guarded_res = z3.If(other.z3_int != 0, raw_res, Z3_ZERO)

        if z3.is_false(self.is_float) and z3.is_false(other.is_float):
            guarded_fp_res = z3.FPVal(0.0, z3.Float64())
            is_float_res = z3.Not(z3.And(self.is_int, other.is_int))
        else:
            left_fp = z3.If(
                self.is_float,
                self.z3_float,
                z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64()),
            )
            right_fp = z3.If(
                other.is_float,
                other.z3_float,
                z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64()),
            )

            safe_right_fp = z3.If(z3.fpIsZero(right_fp), z3.FPVal(1.0, z3.Float64()), right_fp)
            raw_fp_div = z3.fpDiv(z3.RNE(), left_fp, safe_right_fp)

            fp_floored = z3.fpRoundToIntegral(z3.RTN(), raw_fp_div)
            guarded_fp_res = z3.If(
                z3.Not(z3.fpIsZero(right_fp)), fp_floored, z3.fpNaN(z3.Float64())
            )
            is_float_res = z3.Not(z3.And(self.is_int, other.is_int))

        return SymbolicValue(
            _name=f"({self._name}//{other._name})",
            z3_int=guarded_res,
            is_int=z3.And(z3.Or(self.is_int, self.is_bool), z3.Or(other.is_int, other.is_bool)),
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            z3_float=guarded_fp_res,
            is_float=is_float_res,
            is_path=Z3_FALSE,
            affinity_type="float",
        )

    def __truediv__(self, other: object) -> SymbolicValue:
        """Python true division operator with optimized type checking."""
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if (self_affinity == "int" or self_affinity == "float") and (
            other_affinity == "int" or other_affinity == "float"
        ):
            if z3.is_int_value(other.z3_int) and other.z3_int.as_long() == 0:
                raise ZeroDivisionError("division by zero")
            cv = getattr(other, "_constant_value", None)

            if z3.is_false(self.is_float) and z3.is_false(other.is_float):
                left_fp = z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64())
                right_fp = z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64())
            else:
                left_fp = z3.If(
                    self.is_float,
                    self.z3_float,
                    z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64()),
                )
                right_fp = z3.If(
                    other.is_float,
                    other.z3_float,
                    z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64()),
                )

            if cv is not None and cv != 0:
                guarded_float = z3.fpDiv(z3.RNE(), left_fp, right_fp)
                z3_int_placeholder = Z3_ZERO
            else:
                safe_right = z3.If(z3.fpIsZero(right_fp), z3.FPVal(1.0, z3.Float64()), right_fp)
                raw_float = z3.fpDiv(z3.RNE(), left_fp, safe_right)
                guarded_float = z3.If(
                    z3.Not(z3.fpIsZero(right_fp)), raw_float, z3.fpNaN(z3.Float64())
                )
                z3_int_placeholder = z3.If(other.z3_int != 0, Z3_ZERO, Z3_ZERO)

            return SymbolicValue(
                _name=f"({self._name}/{other._name})",
                z3_int=z3_int_placeholder,
                is_int=Z3_FALSE,
                is_float=Z3_TRUE,
                z3_float=guarded_float,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                affinity_type="float",
            )

        if z3.is_int_value(other.z3_int) and other.z3_int.as_long() == 0:
            raise ZeroDivisionError("division by zero")

        cv = getattr(other, "_constant_value", None)

        if z3.is_false(self.is_float) and z3.is_false(other.is_float):
            left_fp = z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64())
            right_fp = z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64())
        else:
            left_fp = z3.If(
                self.is_float,
                self.z3_float,
                z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64()),
            )
            right_fp = z3.If(
                other.is_float,
                other.z3_float,
                z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64()),
            )

        if cv is not None and cv != 0:
            guarded_float = z3.fpDiv(z3.RNE(), left_fp, right_fp)
            z3_int_placeholder = Z3_ZERO
        else:
            safe_right = z3.If(z3.fpIsZero(right_fp), z3.FPVal(1.0, z3.Float64()), right_fp)
            raw_float = z3.fpDiv(z3.RNE(), left_fp, safe_right)
            guarded_float = z3.If(z3.Not(z3.fpIsZero(right_fp)), raw_float, z3.fpNaN(z3.Float64()))
            z3_int_placeholder = z3.If(other.z3_int != 0, Z3_ZERO, Z3_ZERO)

        return SymbolicValue(
            _name=f"({self._name}/{other._name})",
            z3_int=z3_int_placeholder,
            is_int=Z3_FALSE,
            is_float=Z3_TRUE,
            z3_float=guarded_float,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
        )

    def __and__(self, other: object) -> SymbolicValue:
        """Python bitwise/logical AND operator with optimized type checking."""
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            left_bv = int_to_bv(self.z3_int)
            right_bv = int_to_bv(other.z3_int)
            res_bv = left_bv & right_bv
            return SymbolicValue(
                _name=f"({self._name}&{other._name})",
                z3_int=bv_to_int(res_bv),
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
                affinity_type="int",
            )

        if self_affinity == "bool" and other_affinity == "bool":
            return SymbolicValue(
                _name=f"({self._name}&{other._name})",
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=z3.And(self.z3_bool, other.z3_bool),
                is_bool=Z3_TRUE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
                affinity_type="bool",
            )

        left_bv = int_to_bv(self.z3_int)
        right_bv = int_to_bv(other.z3_int)
        res_bv = left_bv & right_bv
        is_int_res = z3.And(z3.Or(self.is_int, self.is_bool), z3.Or(other.is_int, other.is_bool))

        return SymbolicValue(
            _name=f"({self._name}&{other._name})",
            z3_int=bv_to_int(res_bv),
            is_int=is_int_res,
            z3_bool=z3.And(self.z3_bool, other.z3_bool),
            is_bool=z3.And(self.is_bool, other.is_bool),
        )

    def __rand__(self, other: object) -> SymbolicValue:
        """Reflected bitwise AND operator."""

        return self.__and__(other)

    def __or__(self, other: object) -> SymbolicValue:
        """Python bitwise/logical OR operator with optimized type checking."""
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            left_bv = int_to_bv(self.z3_int)
            right_bv = int_to_bv(other.z3_int)
            res_bv = left_bv | right_bv
            return SymbolicValue(
                _name=f"({self._name}|{other._name})",
                z3_int=bv_to_int(res_bv),
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
                affinity_type="int",
            )

        if self_affinity == "bool" and other_affinity == "bool":
            return SymbolicValue(
                _name=f"({self._name}|{other._name})",
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=z3.Or(self.z3_bool, other.z3_bool),
                is_bool=Z3_TRUE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
                affinity_type="bool",
            )

        left_bv = int_to_bv(self.z3_int)
        right_bv = int_to_bv(other.z3_int)
        res_bv = left_bv | right_bv
        is_int_res = z3.And(z3.Or(self.is_int, self.is_bool), z3.Or(other.is_int, other.is_bool))

        return SymbolicValue(
            _name=f"({self._name}|{other._name})",
            z3_int=bv_to_int(res_bv),
            is_int=is_int_res,
            z3_bool=z3.Or(self.z3_bool, other.z3_bool),
            is_bool=z3.And(self.is_bool, other.is_bool),
        )

    def __ror__(self, other: object) -> SymbolicValue:
        """Reflected bitwise OR operator."""

        return self.__or__(other)

    def __xor__(self, other: object) -> SymbolicValue:
        """Python bitwise XOR operator with optimized type checking."""
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            left_bv = int_to_bv(self.z3_int)
            right_bv = int_to_bv(other.z3_int)
            if z3.eq(left_bv, right_bv):
                res_bv = z3.BitVecVal(0, BV_WIDTH)
            elif left_bv.decl().kind() == _Z3_OP_BXOR and left_bv.num_args() == 2:
                a = left_bv.arg(0)
                b = left_bv.arg(1)
                if z3.eq(a, right_bv):
                    res_bv = b
                elif z3.eq(b, right_bv):
                    res_bv = a
                else:
                    res_bv = left_bv ^ right_bv
            elif right_bv.decl().kind() == _Z3_OP_BXOR and right_bv.num_args() == 2:
                a = right_bv.arg(0)
                b = right_bv.arg(1)
                if z3.eq(a, left_bv):
                    res_bv = b
                elif z3.eq(b, left_bv):
                    res_bv = a
                else:
                    res_bv = left_bv ^ right_bv
            else:
                res_bv = left_bv ^ right_bv
            return SymbolicValue(
                _name=f"({self._name}^{other._name})",
                z3_int=bv_to_int(res_bv),
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
                affinity_type="int",
            )

        if self_affinity == "bool" and other_affinity == "bool":
            return SymbolicValue(
                _name=f"({self._name}^{other._name})",
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=z3.Xor(self.z3_bool, other.z3_bool),
                is_bool=Z3_TRUE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
                affinity_type="bool",
            )

        left_bv = int_to_bv(self.z3_int)
        right_bv = int_to_bv(other.z3_int)
        if z3.eq(left_bv, right_bv):
            res_bv = z3.BitVecVal(0, BV_WIDTH)
        elif left_bv.decl().kind() == _Z3_OP_BXOR and left_bv.num_args() == 2:
            a = left_bv.arg(0)
            b = left_bv.arg(1)
            if z3.eq(a, right_bv):
                res_bv = b
            elif z3.eq(b, right_bv):
                res_bv = a
            else:
                res_bv = left_bv ^ right_bv
        elif right_bv.decl().kind() == _Z3_OP_BXOR and right_bv.num_args() == 2:
            a = right_bv.arg(0)
            b = right_bv.arg(1)
            if z3.eq(a, left_bv):
                res_bv = b
            elif z3.eq(b, left_bv):
                res_bv = a
            else:
                res_bv = left_bv ^ right_bv
        else:
            res_bv = left_bv ^ right_bv
        is_int_res = z3.And(z3.Or(self.is_int, self.is_bool), z3.Or(other.is_int, other.is_bool))

        return SymbolicValue(
            _name=f"({self._name}^{other._name})",
            z3_int=bv_to_int(res_bv),
            is_int=is_int_res,
            z3_bool=z3.Xor(self.z3_bool, other.z3_bool),
            is_bool=z3.And(self.is_bool, other.is_bool),
        )

    def __rxor__(self, other: object) -> SymbolicValue:
        """Reflected bitwise XOR operator."""

        return self.__xor__(other)

    def __invert__(self) -> SymbolicValue:
        """Python bitwise inversion operator with optimized type checking."""
        self_affinity = self.affinity_type

        if self_affinity == "int":
            res_bv = ~int_to_bv(self.z3_int)
            res_int = bv_to_int(res_bv)
            return SymbolicValue(
                _name=f"(~{self._name})",
                z3_int=res_int,
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
                affinity_type="int",
            )

        res_bv = ~int_to_bv(self.z3_int)
        res_int = bv_to_int(res_bv)
        is_int_res = z3.simplify(z3.Or(self.is_int, self.is_bool))

        return SymbolicValue(
            _name=f"(~{self._name})",
            z3_int=res_int,
            is_int=is_int_res,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
        )

    def __lshift__(self, other: object) -> SymbolicValue:
        """Python left shift operator (<<) with optimized type checking.

        Performs bitwise left shift. In Python, this is equivalent to
        multiplying by 2**other for non-negative shift amounts.

        Note: Python raises ValueError for negative shift amounts at runtime.
        We model this symbolically using Z3's bitvector left shift which
        handles shifts >= bit width by returning 0.
        """
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            left_bv = int_to_bv(self.z3_int)
            right_bv = int_to_bv(other.z3_int)
            res_bv = left_bv << right_bv
            return SymbolicValue(
                _name=f"({self._name}<<{other._name})",
                z3_int=bv_to_int(res_bv),
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
                affinity_type="int",
            )

        left_bv = int_to_bv(self.z3_int)
        right_bv = int_to_bv(other.z3_int)
        res_bv = left_bv << right_bv
        is_int_res = z3.And(z3.Or(self.is_int, self.is_bool), z3.Or(other.is_int, other.is_bool))

        return SymbolicValue(
            _name=f"({self._name}<<{other._name})",
            z3_int=bv_to_int(res_bv),
            is_int=is_int_res,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            affinity_type="int",
        )

    def __rlshift__(self, other: object) -> SymbolicValue:
        """Reflected left shift operator.

        Called when other << self and other doesn't support __lshift__.
        """
        other = SymbolicValue.from_const(other)
        return other.__lshift__(self)

    def __rshift__(self, other: object) -> SymbolicValue:
        """Python right shift operator (>>) with optimized type checking.

        Performs arithmetic (sign-extending) right shift. In Python, this is
        equivalent to floor division by 2**other for non-negative shift amounts.

        Note: Python raises ValueError for negative shift amounts at runtime.
        We use Z3's arithmetic right shift (bvashr) which preserves the sign bit.
        """
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            left_bv = int_to_bv(self.z3_int)
            right_bv = int_to_bv(other.z3_int)
            res_bv = left_bv >> right_bv
            return SymbolicValue(
                _name=f"({self._name}>>{other._name})",
                z3_int=bv_to_int(res_bv),
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
                affinity_type="int",
            )

        left_bv = int_to_bv(self.z3_int)
        right_bv = int_to_bv(other.z3_int)
        res_bv = left_bv >> right_bv
        is_int_res = z3.And(z3.Or(self.is_int, self.is_bool), z3.Or(other.is_int, other.is_bool))

        return SymbolicValue(
            _name=f"({self._name}>>{other._name})",
            z3_int=bv_to_int(res_bv),
            is_int=is_int_res,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            affinity_type="int",
        )

    def __rrshift__(self, other: object) -> SymbolicValue:
        """Reflected right shift operator.

        Called when other >> self and other doesn't support __rshift__.
        """
        other = SymbolicValue.from_const(other)
        return other.__rshift__(self)

    def __pow__(self, other: object) -> SymbolicValue:
        """Python exponentiation operator with optimized type checking."""
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            res_int = self.z3_int**other.z3_int
            return SymbolicValue(
                _name=f"({self._name}**{other._name})",
                z3_int=res_int,
                is_int=Z3_TRUE,
                z3_float=z3.FPVal(0.0, z3.Float64()),
                is_float=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                affinity_type="int",
            )

        res_int = self.z3_int**other.z3_int
        is_int_res = z3.And(
            z3.Or(self.is_int, self.is_bool), z3.Or(other.is_int, other.is_bool), other.z3_int >= 0
        )

        self_real = z3.ToReal(self.z3_int)
        other_real = z3.ToReal(other.z3_int)

        real_base = z3.If(self.is_float, z3.fpToReal(self.z3_float), self_real)
        real_exp = z3.If(other.is_float, z3.fpToReal(other.z3_float), other_real)

        res_real = real_base**real_exp
        res_float = z3.fpToFP(z3.RNE(), res_real, z3.Float64())

        is_float_res = z3.And(
            z3.Or(self.is_int, self.is_bool, self.is_float),
            z3.Or(other.is_int, other.is_bool, other.is_float),
            z3.Or(
                self.is_float,
                other.is_float,
                z3.And(
                    z3.Or(self.is_int, self.is_bool),
                    z3.Or(other.is_int, other.is_bool),
                    other.z3_int < 0,
                ),
            ),
        )

        return SymbolicValue(
            _name=f"({self._name}**{other._name})",
            z3_int=res_int,
            is_int=is_int_res,
            z3_float=res_float,
            is_float=is_float_res,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            affinity_type="float",
        )

    def logical_not(self) -> SymbolicValue:
        """Python 'not' operator."""
        return SymbolicValue(
            _name=f"(not {self._name})",
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=z3.Not(self.could_be_truthy()),
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )

    def __eq__(self, other: object) -> SymbolicValue:  # type: ignore[override]  # Symbolic types return symbolic booleans, not Python bool
        """Python '==' operator with optimized type checking."""
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            cond = self.z3_int == other.z3_int
            return SymbolicValue(
                _name=f"({self._name}=={other._name})",
                z3_int=z3.If(cond, z3.IntVal(1), Z3_ZERO),
                is_int=Z3_FALSE,
                z3_bool=cond,
                is_bool=Z3_TRUE,
                affinity_type="bool",
            )

        if self_affinity == "bool" and other_affinity == "bool":
            cond = self.z3_bool == other.z3_bool
            return SymbolicValue(
                _name=f"({self._name}=={other._name})",
                z3_int=z3.If(cond, z3.IntVal(1), Z3_ZERO),
                is_int=Z3_FALSE,
                z3_bool=cond,
                is_bool=Z3_TRUE,
                affinity_type="bool",
            )

        self_as_fp = z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64())
        other_as_fp = z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64())
        cond = z3.Or(
            z3.And(self.is_int, other.is_int, self.z3_int == other.z3_int),
            z3.And(self.is_bool, other.is_bool, self.z3_bool == other.z3_bool),
            z3.And(self.is_str, other.is_str, self.z3_str == other.z3_str),
            z3.And(self.is_float, other.is_float, self.z3_float == other.z3_float),
            z3.And(self.is_none, other.is_none),
            z3.And(self.is_obj, other.is_obj, self.z3_addr == other.z3_addr),
            z3.And(self.is_int, other.is_float, other.z3_float == self_as_fp),
            z3.And(self.is_float, other.is_int, self.z3_float == other_as_fp),
            z3.And(
                self.is_bool,
                other.is_int,
                z3.If(self.z3_bool, z3.IntVal(1), Z3_ZERO) == other.z3_int,
            ),
            z3.And(
                self.is_int,
                other.is_bool,
                self.z3_int == z3.If(other.z3_bool, z3.IntVal(1), Z3_ZERO),
            ),
        )
        return SymbolicValue(
            _name=f"({self._name}=={other._name})",
            z3_int=z3.If(cond, z3.IntVal(1), Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=cond,
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )

    def __ne__(self, other: object) -> SymbolicValue:  # type: ignore[override]  # Symbolic types return symbolic booleans, not Python bool
        """Python '!=' operator."""
        return self.__eq__(other).logical_not()

    def __lt__(self, other: object) -> SymbolicValue:
        """Python '<' operator with optimized type checking."""
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            cond = self.z3_int < other.z3_int
            return SymbolicValue(
                _name=f"({self._name}<{other._name})",
                z3_int=z3.If(cond, z3.IntVal(1), Z3_ZERO),
                is_int=Z3_FALSE,
                z3_bool=cond,
                is_bool=Z3_TRUE,
                affinity_type="bool",
            )

        self_as_fp = z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64())
        other_as_fp = z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64())
        cond = z3.Or(
            z3.And(self.is_int, other.is_int, self.z3_int < other.z3_int),
            z3.And(self.is_float, other.is_float, z3.fpLT(self.z3_float, other.z3_float)),
            z3.And(self.is_int, other.is_float, z3.fpLT(self_as_fp, other.z3_float)),
            z3.And(self.is_float, other.is_int, z3.fpLT(self.z3_float, other_as_fp)),
        )
        return SymbolicValue(
            _name=f"({self._name}<{other._name})",
            z3_int=z3.If(cond, z3.IntVal(1), Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=cond,
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )

    def __le__(self, other: object) -> SymbolicValue:
        """Python '<=' operator with optimized type checking."""
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            cond = self.z3_int <= other.z3_int
            return SymbolicValue(
                _name=f"({self._name}<={other._name})",
                z3_int=z3.If(cond, z3.IntVal(1), Z3_ZERO),
                is_int=Z3_FALSE,
                z3_bool=cond,
                is_bool=Z3_TRUE,
                affinity_type="bool",
            )

        self_as_fp = z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64())
        other_as_fp = z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64())
        cond = z3.Or(
            z3.And(self.is_int, other.is_int, self.z3_int <= other.z3_int),
            z3.And(self.is_float, other.is_float, z3.fpLEQ(self.z3_float, other.z3_float)),
            z3.And(self.is_int, other.is_float, z3.fpLEQ(self_as_fp, other.z3_float)),
            z3.And(self.is_float, other.is_int, z3.fpLEQ(self.z3_float, other_as_fp)),
        )
        return SymbolicValue(
            _name=f"({self._name}<={other._name})",
            z3_int=z3.If(cond, z3.IntVal(1), Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=cond,
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )

    def __gt__(self, other: object) -> SymbolicValue:
        """Python '>' operator with optimized type checking."""
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            cond = self.z3_int > other.z3_int
            return SymbolicValue(
                _name=f"({self._name}>{other._name})",
                z3_int=z3.If(cond, z3.IntVal(1), Z3_ZERO),
                is_int=Z3_FALSE,
                z3_bool=cond,
                is_bool=Z3_TRUE,
                affinity_type="bool",
            )

        self_as_fp = z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64())
        other_as_fp = z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64())
        cond = z3.Or(
            z3.And(self.is_int, other.is_int, self.z3_int > other.z3_int),
            z3.And(self.is_float, other.is_float, z3.fpGT(self.z3_float, other.z3_float)),
            z3.And(self.is_int, other.is_float, z3.fpGT(self_as_fp, other.z3_float)),
            z3.And(self.is_float, other.is_int, z3.fpGT(self.z3_float, other_as_fp)),
        )
        return SymbolicValue(
            _name=f"({self._name}>{other._name})",
            z3_int=z3.If(cond, z3.IntVal(1), Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=cond,
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )

    def __ge__(self, other: object) -> SymbolicValue:
        """Python '>=' operator with optimized type checking."""
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            cond = self.z3_int >= other.z3_int
            return SymbolicValue(
                _name=f"({self._name}>={other._name})",
                z3_int=z3.If(cond, z3.IntVal(1), Z3_ZERO),
                is_int=Z3_FALSE,
                z3_bool=cond,
                is_bool=Z3_TRUE,
                affinity_type="bool",
            )

        self_as_fp = z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64())
        other_as_fp = z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64())
        cond = z3.Or(
            z3.And(self.is_int, other.is_int, self.z3_int >= other.z3_int),
            z3.And(self.is_float, other.is_float, z3.fpGEQ(self.z3_float, other.z3_float)),
            z3.And(self.is_int, other.is_float, z3.fpGEQ(self_as_fp, other.z3_float)),
            z3.And(self.is_float, other.is_int, z3.fpGEQ(self.z3_float, other_as_fp)),
        )
        return SymbolicValue(
            _name=f"({self._name}>={other._name})",
            z3_int=z3.If(cond, z3.IntVal(1), Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=cond,
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )

    def __repr__(self) -> str:
        t = self.type_tag
        return f"SymbolicValue(name={self._name}, type={t})"


@dataclass(slots=True)
class SymbolicString(SymbolicType):
    """Symbolic representation of a Python string.

    Uses Z3 sequences (`Seq[Char]`) for core logic.
    """

    _z3_str: z3.SeqRef = field(default_factory=lambda: z3.StringVal(""))
    _z3_len: z3.ArithRef = field(default_factory=lambda: Z3_ZERO)
    _name: str = ""
    _unified: SymbolicValue | None = field(default=None, repr=False, compare=False)

    @property
    def z3_str(self) -> z3.SeqRef:
        if self._unified is not None:
            return self._unified.z3_str
        return self._z3_str

    @property
    def z3_len(self) -> z3.ArithRef:
        if self._unified is not None:
            return z3.Length(self._unified.z3_str)
        return self._z3_len

    @property
    def name(self) -> str:
        return self._name

    @property
    def type_tag(self) -> str:
        return "str"

    def to_z3(self) -> z3.ExprRef:
        return self.z3_str

    def could_be_truthy(self) -> z3.BoolRef:
        if self._unified is not None:
            return self._unified.could_be_truthy()
        return self.z3_len > 0

    def could_be_falsy(self) -> z3.BoolRef:
        if self._unified is not None:
            return self._unified.could_be_falsy()
        return self.z3_len == 0

    def hash_value(self) -> int:
        if self._unified is not None:
            return self._unified.hash_value()
        return self.z3_str.hash() ^ self.z3_len.hash()

    def __add__(self, other: object) -> SymbolicString:
        """String concatenation."""
        if not isinstance(other, (SymbolicString, str)):
            raise TypeError(f"can only concatenate str (not '{type(other).__name__}') to str")
        other_z3 = other.z3_str if isinstance(other, SymbolicString) else z3.StringVal(other)
        other_len = other.z3_len if isinstance(other, SymbolicString) else z3.IntVal(len(other))
        return SymbolicString(
            _z3_str=z3.Concat(self.z3_str, other_z3),
            _z3_len=self.z3_len + other_len,
            _name=f"({self._name}+{getattr(other, 'name', str(other))})",
        )

    @staticmethod
    def symbolic(name: str) -> tuple[SymbolicString, z3.BoolRef]:
        """Create a fresh symbolic string."""
        sv, constraint = SymbolicValue.symbolic(name)
        str_constraint = z3.And(constraint, sv.is_str)
        return SymbolicString(_name=name, _unified=sv), str_constraint

    @staticmethod
    def from_const(value: str) -> SymbolicString:
        """Create a concrete symbolic string."""
        z3_str = z3.StringVal(value)
        z3_len = z3.IntVal(len(value))
        return SymbolicString(_z3_str=z3_str, _z3_len=z3_len, _name=repr(value))

    def __repr__(self) -> str:
        return f"SymbolicString(name={self._name})"

    def length(self) -> z3.ArithRef:
        """Return symbolic string length."""
        return self.z3_len

    def contains(self, sub: object) -> SymbolicValue:
        """Check if string contains a substring sequence."""
        if not isinstance(sub, (SymbolicString, str)):
            raise TypeError("must be str or SymbolicString")
        sub_z3 = sub.z3_str if isinstance(sub, SymbolicString) else z3.StringVal(sub)
        is_contained = z3.Contains(self.z3_str, sub_z3)
        return SymbolicValue(
            _name=f"({self.name} in {getattr(sub, 'name', str(sub))})",
            z3_int=z3.If(is_contained, z3.IntVal(1), Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=is_contained,
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )

    def startswith(self, prefix: object) -> SymbolicValue:
        """Check if string starts with prefix."""
        if not isinstance(prefix, (SymbolicString, str)):
            raise TypeError("must be str or SymbolicString")
        prefix_z3 = prefix.z3_str if isinstance(prefix, SymbolicString) else z3.StringVal(prefix)
        cond = z3.PrefixOf(prefix_z3, self.z3_str)
        return SymbolicValue(
            _name=f"{self.name}.startswith(...)",
            z3_int=z3.If(cond, z3.IntVal(1), Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=cond,
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )

    def endswith(self, suffix: object) -> SymbolicValue:
        """Check if string ends with suffix."""
        if not isinstance(suffix, (SymbolicString, str)):
            raise TypeError("must be str or SymbolicString")
        suffix_z3 = suffix.z3_str if isinstance(suffix, SymbolicString) else z3.StringVal(suffix)
        cond = z3.SuffixOf(suffix_z3, self.z3_str)
        return SymbolicValue(
            _name=f"{self.name}.endswith(...)",
            z3_int=z3.If(cond, z3.IntVal(1), Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=cond,
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )

    def substring(self, start: object, end: object) -> SymbolicString:
        """Extract a substring from start to end."""
        start_raw = getattr(start, "z3_int", start)
        end_raw = getattr(end, "z3_int", end)
        if isinstance(start_raw, int):
            s = z3.IntVal(start_raw)
        elif isinstance(start_raw, z3.ArithRef):
            s = start_raw
        else:
            raise TypeError("substring start must be an integer or symbolic integer")
        if isinstance(end_raw, int):
            e = z3.IntVal(end_raw)
        elif isinstance(end_raw, z3.ArithRef):
            e = end_raw
        else:
            raise TypeError("substring end must be an integer or symbolic integer")
        len_s = e - s
        sub = z3.If(
            z3.And(s >= 0, len_s >= 0), z3.SubString(self.z3_str, s, len_s), z3.StringVal("")
        )
        return SymbolicString(
            _z3_str=sub,
            _z3_len=z3.Length(sub),
            _name=f"({self._name}[{s}:{e}])",
        )

    def conditional_merge(self, other: AnySymbolic, condition: z3.BoolRef) -> SymbolicValue:
        """Merge this string with another based on *condition*.

        Returns a SymbolicValue (the universal type) to handle heterogeneous merges.
        """
        return SymbolicValue.from_specialized(self).conditional_merge(other, condition)


def __getattr__(name: str) -> type:
    if name in ("SymbolicDict", "SymbolicList", "SymbolicObject"):
        from pysymex.core.types.containers import SymbolicDict, SymbolicList, SymbolicObject

        if name == "SymbolicDict":
            return SymbolicDict
        if name == "SymbolicList":
            return SymbolicList
        if name == "SymbolicObject":
            return SymbolicObject
    raise AttributeError(f"module {__name__} has no attribute {name}")
