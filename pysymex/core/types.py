"""Core symbolic types for pysymex.
This module defines the symbolic type system that bridges Python's dynamic
typing with Z3's static typing. Each Python value is represented as a
union of possible Z3 types with type discriminators.
"""

from __future__ import annotations

import dataclasses as _dataclasses
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any
from typing import cast as _cast

import z3

from pysymex.core.addressing import next_address

AnySymbolic = Any


_FROM_CONST_CACHE_LOCK = threading.Lock()


Z3_TRUE: z3.BoolRef = z3.BoolVal(True)
Z3_FALSE: z3.BoolRef = z3.BoolVal(False)
Z3_ZERO: z3.ArithRef = z3.IntVal(0)


_BV_WIDTH: int = 64


def _int_to_bv(expr: z3.ArithRef) -> z3.BitVecRef:
    """Convert a Z3 integer expression to a 64-bit bitvector."""
    return z3.Int2BV(expr, _BV_WIDTH)


def _bv_to_int(expr: z3.BitVecRef) -> z3.ArithRef:
    """Convert a Z3 bitvector back to a (signed) integer."""
    return z3.BV2Int(expr, is_signed=True)


FROM_CONST_CACHE: dict[str | tuple[str, int], SymbolicValue] = {}
FROM_CONST_CACHE_LIMIT: int = 512


SYMBOLIC_CACHE: dict[str, tuple[SymbolicValue, z3.BoolRef]] = {}
SYMBOLIC_CACHE_LIMIT: int = 1024


def _merge_taint(
    a: frozenset[str] | set[str] | None,
    b: frozenset[str] | set[str] | None,
) -> frozenset[str] | None:
    """Merge two taint-label sets into a frozen set.

    Handles None inputs (meaning 'no taint') gracefully:
    - None + None → None
    - None + labels → labels
    - labels + None → labels
    - labels + labels → union
    """
    if a is None and b is None:
        return None
    if not a:
        return frozenset(b) if b else None
    if not b:
        return frozenset(a)
    return frozenset(a | b)


int_to_bv = _int_to_bv
bv_to_int = _bv_to_int
merge_taint = _merge_taint


def fresh_name(prefix: str) -> str:
    """Generate a unique symbolic variable name.

    Delegates to :func:`pysymex.core.addressing.next_address` which uses a
    ``contextvars.ContextVar`` counter, giving each async session its own
    isolated namespace and eliminating cross-session Z3 variable collisions.
    """
    return f"{prefix}_{next_address()}"


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
    """Abstract base class for the PySyMex symbolic type system.

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

    def __post_init__(self):
        if self._name:
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

    def as_unified(self) -> SymbolicValue:
        """Convert to unified SymbolicValue."""
        return SymbolicValue(
            _name=self._name,
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_none=Z3_TRUE,
            is_path=Z3_FALSE,
            _h_active=self._h_active,
            taint_labels=None,
        )

    def conditional_merge(self, other: AnySymbolic, condition: z3.BoolRef) -> AnySymbolic:
        """Merge with another value based on a condition."""
        if isinstance(other, SymbolicNone):
            return self
        return self.as_unified().conditional_merge(other, condition)

    def __repr__(self) -> str:
        return "SymbolicNone()"


@dataclass(slots=True)
class SymbolicValue(SymbolicType):
    """An optimized 'any' type representing a union of potential Python values.

    **Encoding Strategy:**
    PySyMex represents dynamic types as a collection of Z3 expressions with 
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
        taint_labels: Abstract security metadata tags (not used for Z3 logic).
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
    taint_labels: frozenset[str] | None = field(default=None, compare=False)
    _constant_value: object = field(default=None, compare=False, repr=False)
    _bv_cache: z3.BitVecRef | None = field(default=None, init=False, repr=False, compare=False)

    affinity_type: str = field(default="NoneType", compare=False)
    _h_active: bool = field(default=False)

    def __post_init__(self):
        if self._name:
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

    @property
    def name(self) -> str:
        """Return the name of the symbolic value."""
        return self._name

    @property
    def type_tag(self) -> str:
        """Return the type tag of the symbolic value."""
        if self._type:
            return self._type
        if self.is_float == Z3_TRUE:
            return "float"
        if self.is_int == Z3_TRUE:
            return "int"
        if self.is_bool == Z3_TRUE:
            return "bool"
        if self.is_str == Z3_TRUE:
            return "str"
        return "unknown"

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
        could be truthy."""
        cached = self._truthy_cache
        if cached is not None:
            return cached
        result = z3.Or(
            z3.And(self.is_bool, self.z3_bool),
            z3.And(self.is_int, self.z3_int != 0),
            z3.And(self.is_str, z3.Length(self.z3_str) > 0),
            z3.And(self.is_float, z3.Not(z3.fpIsZero(self.z3_float))),
            self.is_path,
            self.is_list,
            self.is_dict,
        )
        self._truthy_cache = result
        return result

    def could_be_falsy(self) -> z3.BoolRef:
        """Return a Z3 boolean expression that is true if the symbolic value
        could be falsy."""
        cached = self._falsy_cache
        if cached is not None:
            return cached
        result = z3.Or(
            z3.And(self.is_bool, z3.Not(self.z3_bool)),
            z3.And(self.is_int, self.z3_int == 0),
            z3.And(self.is_str, z3.Length(self.z3_str) == 0),
            self.is_none,
        )
        self._falsy_cache = result
        return result

    def with_taint(self, label: str | set[str] | frozenset[str]) -> SymbolicValue:
        """Return a copy with added taint."""
        new_labels = set(self.taint_labels or set())
        if isinstance(label, str):
            new_labels.add(label)
        else:
            new_labels.update(label)
        return _dataclasses.replace(self, taint_labels=frozenset(new_labels))

    def conditional_merge(self, other: AnySymbolic, condition: z3.BoolRef) -> SymbolicValue:
        """Merge with another value based on a condition: If(condition, self, other)."""
        if isinstance(other, SymbolicNone):
            return other.conditional_merge(self, z3.Not(condition))
        if not isinstance(other, (SymbolicValue, SymbolicType)):
            other = SymbolicValue.from_const(other)

        other_int = getattr(other, "z3_int", Z3_ZERO)
        other_is_int = getattr(other, "is_int", Z3_FALSE)
        other_bool = getattr(other, "z3_bool", Z3_FALSE)
        other_is_bool = getattr(other, "is_bool", Z3_FALSE)
        other_str = getattr(other, "z3_str", z3.StringVal(""))
        other_is_str = getattr(other, "is_str", Z3_FALSE)
        other_addr = getattr(other, "z3_addr", getattr(other, "address", Z3_ZERO))
        other_is_obj = getattr(other, "is_obj", Z3_TRUE if hasattr(other, "address") else Z3_FALSE)
        other_is_none = getattr(other, "is_none", Z3_FALSE)
        other_is_path = getattr(other, "is_path", Z3_FALSE)
        other_float = getattr(other, "z3_float", z3.FPVal(0.0, z3.Float64()))
        other_is_float = getattr(other, "is_float", Z3_FALSE)
        other_array = getattr(other, "z3_array", None)
        other_is_list = getattr(other, "is_list", Z3_FALSE)
        other_is_dict = getattr(other, "is_dict", Z3_FALSE)

        return SymbolicValue(
            _name=f"If({condition}, {self._name}, {getattr(other, 'name', 'other')})",
            z3_int=z3.If(condition, self.z3_int, other_int),
            is_int=z3.If(condition, self.is_int, other_is_int),
            z3_bool=z3.If(condition, self.z3_bool, other_bool),
            is_bool=z3.If(condition, self.is_bool, other_is_bool),
            z3_str=z3.If(condition, self.z3_str, other_str),
            is_str=z3.If(condition, self.is_str, other_is_str),
            z3_addr=z3.If(condition, self.z3_addr, other_addr),
            is_obj=z3.If(condition, self.is_obj, other_is_obj),
            is_path=z3.If(condition, self.is_path, other_is_path),
            is_none=z3.If(condition, self.is_none, other_is_none),
            z3_float=z3.If(condition, self.z3_float, other_float),
            is_float=z3.If(condition, self.is_float, other_is_float),
            z3_array=(
                z3.If(condition, self.z3_array, other_array)
                if (self.z3_array is not None and other_array is not None)
                else (self.z3_array if self.z3_array is not None else other_array)
            ),
            is_list=z3.If(condition, self.is_list, other_is_list),
            is_dict=z3.If(condition, self.is_dict, other_is_dict),
            taint_labels=_merge_taint(self.taint_labels, getattr(other, "taint_labels", None)),
            _h_active=self._h_active or getattr(other, "_h_active", False),
        )

    def as_string(self) -> "SymbolicString":
        """Downcast this unified value back to a SymbolicString."""
        from pysymex.core.types import SymbolicString
        return SymbolicString(
            _z3_str=self.z3_str,
            _z3_len=z3.Length(self.z3_str),
            _name=self._name,
            _unified=self,
        )

    def as_unified(self) -> SymbolicValue:
        return self

    @staticmethod
    def symbolic(name: str) -> tuple[SymbolicValue, z3.BoolRef]:
        """Create a fresh symbolic value with type constraint.

        This method creates a truly 'any' type symbolic value that can be an
        Integer, Boolean, String, Path, Object (address), or None.
        """
        id_suffix = next_address()
        z3_int = z3.Int(f"{name}_{id_suffix}_int")
        z3_bool = z3.Bool(f"{name}_{id_suffix}_bool")
        z3_str = z3.String(f"{name}_{id_suffix}_str")
        z3_addr = z3.Int(f"{name}_{id_suffix}_addr")
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

        # At least one must be true
        at_least_one = z3.Or(*type_vars)
        # At most one must be true (pairwise exclusion)
        at_most_one = []
        for i in range(len(type_vars)):
            for j in range(i + 1, len(type_vars)):
                at_most_one.append(z3.Not(z3.And(type_vars[i], type_vars[j])))

        type_constraint = z3.And(at_least_one, *at_most_one)

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
            object.__setattr(sv, "_h_active", True)
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
            object.__setattr(sv, "_h_active", True)
        return sv, Z3_TRUE

    @staticmethod
    def from_specialized(value: object) -> SymbolicValue:
        """Convert a specialized SymbolicType to a unified SymbolicValue."""
        if hasattr(value, "as_unified"):
            return _cast("SymbolicValue", _cast("Any", value).as_unified())
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
            sv = SymbolicValue(
                _name=str(value),
                z3_int=z3.IntVal(int(value)),
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

        if hasattr(value, "as_unified"):
            return _cast("SymbolicValue", _cast("Any", value).as_unified())

        if isinstance(value, str):
            from pysymex.core.types import SymbolicString
            return _cast("SymbolicValue", SymbolicString.from_const(value).as_unified())

        sv = SymbolicValue(
            _name=str(value),
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_path=Z3_FALSE,
            _constant_value=value,
        )
        if isinstance(value, (tuple, list, dict)):
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
                object.__setattr(val, "_h_active", True)
                
        return val, path_constraint

    def __add__(self, other: object) -> SymbolicValue:
        """Python addition operator."""
        other = SymbolicValue.from_const(other)
        res_int = self.z3_int + other.z3_int
        is_int_res = z3.And(self.is_int, other.is_int)
        
        left_fp = z3.If(self.is_float, self.z3_float, z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64()))
        right_fp = z3.If(other.is_float, other.z3_float, z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64()))
        res_float = z3.fpAdd(z3.RNE(), left_fp, right_fp)
        is_float_res = z3.Or(self.is_float, other.is_float)

        return SymbolicValue(
            _name=f"({self._name}+{other._name})",
            z3_int=res_int,
            is_int=is_int_res,
            z3_float=res_float,
            is_float=is_float_res,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    def __sub__(self, other: object) -> SymbolicValue:
        """Python subtraction operator."""
        other = SymbolicValue.from_const(other)
        res_int = self.z3_int - other.z3_int
        is_int_res = z3.And(self.is_int, other.is_int)
        
        left_fp = z3.If(self.is_float, self.z3_float, z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64()))
        right_fp = z3.If(other.is_float, other.z3_float, z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64()))
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
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    def __mul__(self, other: object) -> SymbolicValue:
        """Python multiplication operator."""
        other = SymbolicValue.from_const(other)
        res_int = self.z3_int * other.z3_int
        is_int_res = z3.And(self.is_int, other.is_int)
        
        left_fp = z3.If(self.is_float, self.z3_float, z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64()))
        right_fp = z3.If(other.is_float, other.z3_float, z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64()))
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
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    def __neg__(self) -> SymbolicValue:
        """Python negation operator."""
        return SymbolicValue(
            _name=f"(-{self._name})",
            z3_int=-self.z3_int,
            is_int=self.is_int,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            taint_labels=self.taint_labels,
            affinity_type="int",
        )

    def __mod__(self, other: object) -> SymbolicValue:
        """Python modulo operator."""
        other = SymbolicValue.from_const(other)
        if z3.is_int_value(other.z3_int) and other.z3_int.as_long() == 0:
            raise ZeroDivisionError("division by zero")
        safe_divisor = _guarded_nonzero_divisor(other.z3_int)
        return SymbolicValue(
            _name=f"({self._name}%{other._name})",
            z3_int=_py_mod(self.z3_int, safe_divisor),
            is_int=z3.And(self.is_int, other.is_int),
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
            affinity_type="int",
        )

    def __floordiv__(self, other: object) -> SymbolicValue:
        """Python floor division operator."""
        other = SymbolicValue.from_const(other)
        if z3.is_int_value(other.z3_int) and other.z3_int.as_long() == 0:
            raise ZeroDivisionError("division by zero")
        safe_divisor = _guarded_nonzero_divisor(other.z3_int)
        return SymbolicValue(
            _name=f"({self._name}//{other._name})",
            z3_int=_py_floor_div(self.z3_int, safe_divisor),
            is_int=z3.And(self.is_int, other.is_int),
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_path=Z3_FALSE,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
            affinity_type="int",
        )

    def __truediv__(self, other: object) -> SymbolicValue:
        """Python true division operator."""
        other = SymbolicValue.from_const(other)
        if z3.is_int_value(other.z3_int) and other.z3_int.as_long() == 0:
            raise ZeroDivisionError("division by zero")
        
        left_fp = z3.If(self.is_float, self.z3_float, z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64()))
        right_fp = z3.If(other.is_float, other.z3_float, z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64()))
        res_float = z3.fpDiv(z3.RNE(), left_fp, right_fp)
        
        return SymbolicValue(
            _name=f"({self._name}/{other._name})",
            z3_int=self.z3_int / _guarded_nonzero_divisor(other.z3_int),
            is_int=Z3_FALSE,
            is_float=Z3_TRUE,
            z3_float=res_float,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    def __and__(self, other: object) -> SymbolicValue:
        """Python bitwise/logical AND operator."""
        other = SymbolicValue.from_const(other)
        left_bv = int_to_bv(self.z3_int)
        right_bv = int_to_bv(other.z3_int)
        res_bv = left_bv & right_bv
        
        return SymbolicValue(
            _name=f"({self._name}&{other._name})",
            z3_int=bv_to_int(res_bv),
            is_int=z3.And(self.is_int, other.is_int),
            z3_bool=z3.And(self.z3_bool, other.z3_bool),
            is_bool=z3.And(self.is_bool, other.is_bool),
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    def __or__(self, other: object) -> SymbolicValue:
        """Python bitwise/logical OR operator."""
        other = SymbolicValue.from_const(other)
        left_bv = int_to_bv(self.z3_int)
        right_bv = int_to_bv(other.z3_int)
        res_bv = left_bv | right_bv
        
        return SymbolicValue(
            _name=f"({self._name}|{other._name})",
            z3_int=bv_to_int(res_bv),
            is_int=z3.And(self.is_int, other.is_int),
            z3_bool=z3.Or(self.z3_bool, other.z3_bool),
            is_bool=z3.And(self.is_bool, other.is_bool),
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    def __xor__(self, other: object) -> SymbolicValue:
        """Python bitwise XOR operator."""
        other = SymbolicValue.from_const(other)
        left_bv = int_to_bv(self.z3_int)
        right_bv = int_to_bv(other.z3_int)
        res_bv = left_bv ^ right_bv
        
        return SymbolicValue(
            _name=f"({self._name}^{other._name})",
            z3_int=bv_to_int(res_bv),
            is_int=z3.And(self.is_int, other.is_int),
            z3_bool=z3.Xor(self.z3_bool, other.z3_bool),
            is_bool=z3.And(self.is_bool, other.is_bool),
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    def __invert__(self) -> SymbolicValue:
        """Python bitwise inversion operator."""
        res_bv = ~int_to_bv(self.z3_int)
        return SymbolicValue(
            _name=f"(~{self._name})",
            z3_int=bv_to_int(res_bv),
            is_int=self.is_int,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            taint_labels=self.taint_labels,
        )

    def __pow__(self, other: object) -> SymbolicValue:
        """Python exponentiation operator."""
        other = SymbolicValue.from_const(other)
        # Note: Z3's ** operator is only defined for real/int and can be
        # extremely expensive or non-linear.
        return SymbolicValue(
            _name=f"({self._name}**{other._name})",
            z3_int=self.z3_int**other.z3_int,
            is_int=z3.And(self.is_int, other.is_int),
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
            affinity_type="int",
        )

    def logical_not(self) -> SymbolicValue:
        """Python 'not' operator."""
        return SymbolicValue(
            _name=f"(not {self._name})",
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=z3.Not(self.could_be_truthy()),
            is_bool=Z3_TRUE,
            taint_labels=self.taint_labels,
            affinity_type="bool",
        )

    def __eq__(self, other: object) -> SymbolicValue:  # type: ignore[override]
        """Python '==' operator."""
        other = SymbolicValue.from_const(other)
        cond = z3.Or(
            z3.And(self.is_int, other.is_int, self.z3_int == other.z3_int),
            z3.And(self.is_bool, other.is_bool, self.z3_bool == other.z3_bool),
            z3.And(self.is_str, other.is_str, self.z3_str == other.z3_str),
            z3.And(self.is_float, other.is_float, self.z3_float == other.z3_float),
            z3.And(self.is_none, other.is_none),
            z3.And(self.is_obj, other.is_obj, self.z3_addr == other.z3_addr),
        )
        return SymbolicValue(
            _name=f"({self._name}=={other._name})",
            z3_int=z3.If(cond, z3.IntVal(1), Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=cond,
            is_bool=Z3_TRUE,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
            affinity_type="bool",
        )

    def __ne__(self, other: object) -> SymbolicValue:  # type: ignore[override]
        """Python '!=' operator."""
        return self.__eq__(other).logical_not()

    def __lt__(self, other: object) -> SymbolicValue:
        """Python '<' operator."""
        other = SymbolicValue.from_const(other)
        cond = z3.Or(
            z3.And(self.is_int, other.is_int, self.z3_int < other.z3_int),
            z3.And(self.is_float, other.is_float, z3.fpLT(self.z3_float, other.z3_float)),
        )
        return SymbolicValue(
            _name=f"({self._name}<{other._name})",
            z3_int=z3.If(cond, z3.IntVal(1), Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=cond,
            is_bool=Z3_TRUE,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
            affinity_type="bool",
        )

    def __le__(self, other: object) -> SymbolicValue:
        """Python '<=' operator."""
        other = SymbolicValue.from_const(other)
        cond = z3.Or(
            z3.And(self.is_int, other.is_int, self.z3_int <= other.z3_int),
            z3.And(self.is_float, other.is_float, z3.fpLEQ(self.z3_float, other.z3_float)),
        )
        return SymbolicValue(
            _name=f"({self._name}<={other._name})",
            z3_int=z3.If(cond, z3.IntVal(1), Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=cond,
            is_bool=Z3_TRUE,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
            affinity_type="bool",
        )

    def __gt__(self, other: object) -> SymbolicValue:
        """Python '>' operator."""
        other = SymbolicValue.from_const(other)
        cond = z3.Or(
            z3.And(self.is_int, other.is_int, self.z3_int > other.z3_int),
            z3.And(self.is_float, other.is_float, z3.fpGT(self.z3_float, other.z3_float)),
        )
        return SymbolicValue(
            _name=f"({self._name}>{other._name})",
            z3_int=z3.If(cond, z3.IntVal(1), Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=cond,
            is_bool=Z3_TRUE,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
            affinity_type="bool",
        )

    def __ge__(self, other: object) -> SymbolicValue:
        """Python '>=' operator."""
        other = SymbolicValue.from_const(other)
        cond = z3.Or(
            z3.And(self.is_int, other.is_int, self.z3_int >= other.z3_int),
            z3.And(self.is_float, other.is_float, z3.fpGEQ(self.z3_float, other.z3_float)),
        )
        return SymbolicValue(
            _name=f"({self._name}>={other._name})",
            z3_int=z3.If(cond, z3.IntVal(1), Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=cond,
            is_bool=Z3_TRUE,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
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
    taint_labels: frozenset[str] | None = field(default=None)
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

    def as_unified(self) -> SymbolicValue:
        """Convert to unified SymbolicValue."""
        return SymbolicValue(
            _name=self._name,
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            z3_str=self.z3_str,
            is_str=Z3_TRUE,
            is_none=Z3_FALSE,
            is_path=Z3_FALSE,
            taint_labels=self.taint_labels,
            affinity_type="str",
        )

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
            taint_labels=_merge_taint(self.taint_labels, getattr(other, "taint_labels", None)),
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

    def with_taint(self, label: str | set[str] | frozenset[str]) -> SymbolicString:
        """Return a copy with added taint."""
        new_labels = set(self.taint_labels or set())
        if isinstance(label, str):
            new_labels.add(label)
        else:
            new_labels.update(label)
        return _dataclasses.replace(self, taint_labels=frozenset(new_labels))

    def length(self) -> z3.ArithRef:
        """Return symbolic string length."""
        return self.z3_len

    def substring(self, start: object, end: object) -> SymbolicString:
        """Extract a substring from start to end, propagating taint."""
        s = getattr(start, "z3_int", start)
        e = getattr(end, "z3_int", end)
        sub = z3.SubString(self.z3_str, s, e - s)
        return SymbolicString(
            _z3_str=sub,
            _z3_len=z3.Length(sub),
            _name=f"({self._name}[{s}:{e}])",
            taint_labels=self.taint_labels,
        )

    def conditional_merge(self, other: AnySymbolic, condition: z3.BoolRef) -> SymbolicValue:
        """Merge this string with another based on *condition*.

        Returns a SymbolicValue (the universal type) to handle heterogeneous merges.
        """
        return self.as_unified().conditional_merge(other, condition)


# Re-export container types for legacy imports lazily to break circularity.
def __getattr__(name: str) -> type:
    if name in ("SymbolicDict", "SymbolicList", "SymbolicObject"):
        from pysymex.core.types_containers import SymbolicDict, SymbolicList, SymbolicObject
        if name == "SymbolicDict": return SymbolicDict
        if name == "SymbolicList": return SymbolicList
        if name == "SymbolicObject": return SymbolicObject
    raise AttributeError(f"module {__name__} has no attribute {name}")


