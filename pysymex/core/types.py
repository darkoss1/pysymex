"""Core symbolic types for pysymex.
This module defines the symbolic type system that bridges Python's dynamic
typing with Z3's static typing. Each Python value is represented as a
union of possible Z3 types with type discriminators.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from dataclasses import dataclass, field

from typing import TYPE_CHECKING, Union, Any

import z3

if TYPE_CHECKING:
    pass

_sym_counter = 0


Z3_TRUE: z3.BoolRef = z3.BoolVal(True)

Z3_FALSE: z3.BoolRef = z3.BoolVal(False)

Z3_ZERO: z3.ArithRef = z3.IntVal(0)


FROM_CONST_CACHE: dict[str | tuple[str, int], "SymbolicValue"] = {}

FROM_CONST_CACHE_LIMIT: int = 512


SYMBOLIC_CACHE: dict[str, tuple[SymbolicValue, z3.BoolRef]] = {}

SYMBOLIC_CACHE_LIMIT: int = 1024


def _merge_taint(a: frozenset[str] | None, b: frozenset[str] | None) -> frozenset[str] | None:
    """Merge two taint-label sets with a fast-path for the common None|None case.

    Avoids creating two temporary ``frozenset()`` objects when neither
    operand carries taint (the overwhelmingly common case).
    """

    if a is None:
        return b

    if b is None:
        return a

    return a | b


def fresh_name(prefix: str) -> str:
    """Generate a unique symbolic variable name."""

    global _sym_counter

    _sym_counter += 1

    return f"{prefix}_{_sym_counter}"


class SymbolicType(ABC):
    """Abstract base class for all symbolic types."""

    __slots__ = ()

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name for debugging."""

    @abstractmethod
    def to_z3(self) -> z3.ExprRef:
        """Convert to primary Z3 expression."""

    @abstractmethod
    def could_be_truthy(self) -> z3.BoolRef:
        """Z3 expression for when this value is truthy."""

    @abstractmethod
    def could_be_falsy(self) -> z3.BoolRef:
        """Z3 expression for when this value is falsy."""


@dataclass(slots=True)
class SymbolicNone(SymbolicType):
    """Represents Python None."""

    _name: str = field(default_factory=lambda: fresh_name("none"))

    @property
    def name(self) -> str:
        return "None"

    def to_z3(self) -> z3.ExprRef:
        return Z3_FALSE

    def could_be_truthy(self) -> z3.BoolRef:
        return Z3_FALSE

    def could_be_falsy(self) -> z3.BoolRef:
        return Z3_TRUE

    def conditional_merge(self, other: AnySymbolic, condition: z3.BoolRef) -> AnySymbolic:
        """Merge with another value based on a condition."""

        if isinstance(other, SymbolicNone):
            return self

        if hasattr(other, "address") or hasattr(other, "z3_string") or hasattr(other, "z3_array"):
            return other.conditional_merge(self, z3.Not(condition))

        fresh_name("merge_none")

        return SymbolicValue(
            _name=f"If({condition}, None, {other.name})",
            z3_int=z3.If(condition, Z3_ZERO, other.to_z3()),
            is_int=z3.If(condition, Z3_FALSE, getattr(other, "is_int", Z3_FALSE)),
            z3_bool=z3.If(condition, Z3_FALSE, getattr(other, "z3_bool", Z3_FALSE)),
            is_bool=z3.If(condition, Z3_FALSE, getattr(other, "is_bool", Z3_FALSE)),
            is_none=z3.If(condition, Z3_TRUE, getattr(other, "is_none", Z3_FALSE)),
            is_path=z3.If(condition, Z3_FALSE, getattr(other, "is_path", Z3_FALSE)),
            taint_labels=(
                (getattr(other, "taint_labels", set()) or frozenset())
                if getattr(other, "taint_labels", None)
                else None
            ),
        )

    def __repr__(self) -> str:
        return "SymbolicNone()"


@dataclass(slots=True)
class SymbolicValue(SymbolicType):
    """Union type representing an integer or boolean symbolic value.

    **Memory layout (slots=True, hot fields first):**
    Fields are ordered so that the four Z3 references accessed on every
    branch / comparison (z3_int, is_int, z3_bool, is_bool) occupy
    adjacent slot positions.  CPython 3.10+ lays slots out in declaration
    order, so these four 8-byte pointers share the same 64-byte L1 cache
    line, minimizing cache misses on the hot path.

    Attributes:
        z3_int: Z3 integer expression (hot)
        is_int: Z3 boolean - True if this is an integer (hot)
        z3_bool: Z3 boolean expression (hot)
        is_bool: Z3 boolean - True if this is a boolean (hot)
        _name: Debugging name (cold)
        is_path: Z3 boolean - True if this is a path (cold)
        is_none: Z3 boolean - True if this could be None (cold)
        taint_labels: Optional taint labels (cold)
    """

    z3_int: z3.ArithRef

    is_int: z3.BoolRef

    z3_bool: z3.BoolRef

    is_bool: z3.BoolRef

    _name: str = ""

    is_path: z3.BoolRef = field(default_factory=lambda: Z3_FALSE)

    is_none: z3.BoolRef = field(default_factory=lambda: Z3_FALSE)

    taint_labels: set[str] | frozenset[str] | None = field(default=None, compare=False)

    _truthy_cache: z3.BoolRef | None = field(default=None, init=False, repr=False, compare=False)

    _falsy_cache: z3.BoolRef | None = field(default=None, init=False, repr=False, compare=False)

    model_name: str | None = field(default=None, init=False, repr=False, compare=False)

    _enhanced_object: object | None = field(default=None, init=False, repr=False, compare=False)

    _type: str | None = field(default=None, init=False, repr=False, compare=False)

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_int

    def could_be_truthy(self) -> z3.BoolRef:
        cached = self._truthy_cache

        if cached is not None:
            return cached

        result = z3.Or(
            z3.And(self.is_bool, self.z3_bool),
            z3.And(self.is_int, self.z3_int != 0),
            self.is_path,
        )

        self._truthy_cache = result

        return result

    def could_be_falsy(self) -> z3.BoolRef:
        cached = self._falsy_cache

        if cached is not None:
            return cached

        result = z3.Or(
            z3.And(self.is_bool, z3.Not(self.z3_bool)),
            z3.And(self.is_int, self.z3_int == 0),
            self.is_none,
        )

        self._falsy_cache = result

        return result

    def with_taint(self, label: str | set[str] | frozenset[str]) -> SymbolicValue:
        """Return a copy with added taint."""

        import dataclasses

        new_labels = set(self.taint_labels or set())

        if isinstance(label, str):
            new_labels.add(label)

        else:
            new_labels.update(label)

        return dataclasses.replace(self, taint_labels=frozenset(new_labels))

    def conditional_merge(self, other: AnySymbolic, condition: z3.BoolRef) -> SymbolicValue:
        """Merge with another value based on a condition: If(condition, self, other)."""

        if isinstance(other, SymbolicNone):
            return other.conditional_merge(self, z3.Not(condition))

        if not isinstance(other, SymbolicValue):
            other = SymbolicValue.from_const(other)

        new_int = z3.If(condition, self.z3_int, other.z3_int)

        new_is_int = z3.If(condition, self.is_int, other.is_int)

        new_bool = z3.If(condition, self.z3_bool, other.z3_bool)

        new_is_bool = z3.If(condition, self.is_bool, other.is_bool)

        new_is_path = z3.If(condition, self.is_path, other.is_path)

        new_is_none = z3.If(condition, self.is_none, getattr(other, "is_none", Z3_FALSE))

        return SymbolicValue(
            _name=f"If({condition}, {self._name}, {other.name})",
            z3_int=new_int,
            is_int=new_is_int,
            z3_bool=new_bool,
            is_bool=new_is_bool,
            is_path=new_is_path,
            is_none=new_is_none,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    @staticmethod
    def symbolic(name: str) -> tuple[SymbolicValue, z3.BoolRef]:
        """Create a fresh symbolic value with type constraint.

        Results are cached by *name* in a process-wide dict.  Z3 variables
        with the same string name map to the same AST node, so returning
        the cached pair is semantically identical to creating fresh ones.
        This eliminates thousands of ctypes round-trips when the same
        parameter names recur across analysis passes.
        """

        cached = SYMBOLIC_CACHE.get(name)

        if cached is not None:
            return cached

        z3_int = z3.Int(f"{name}_int")

        z3_bool = z3.Bool(f"{name}_bool")

        is_int = z3.Bool(f"{name}_is_int")

        is_bool = z3.Bool(f"{name}_is_bool")

        is_path = z3.Bool(f"{name}_is_path")

        type_constraint = z3.And(
            z3.Or(is_int, is_bool, is_path),
            z3.Not(z3.And(is_int, is_bool)),
            z3.Not(z3.And(is_int, is_path)),
            z3.Not(z3.And(is_bool, is_path)),
        )

        result = (
            SymbolicValue(
                z3_int=z3_int,
                is_int=is_int,
                z3_bool=z3_bool,
                is_bool=is_bool,
                _name=name,
                is_path=is_path,
            ),
            type_constraint,
        )

        if len(SYMBOLIC_CACHE) < SYMBOLIC_CACHE_LIMIT:
            SYMBOLIC_CACHE[name] = result

        return result

    @staticmethod
    def from_const(value: object) -> SymbolicValue:
        """Create a concrete symbolic value from a Python constant.

        Caches None, True, False, and small integers to avoid repeated
        Z3 allocation.
        """

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
            )

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
                )

            else:
                sv = SymbolicValue(
                    _name="False",
                    z3_int=Z3_ZERO,
                    is_int=Z3_FALSE,
                    z3_bool=Z3_FALSE,
                    is_bool=Z3_TRUE,
                    is_path=Z3_FALSE,
                )

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
                is_path=Z3_FALSE,
            )

            if len(FROM_CONST_CACHE) < FROM_CONST_CACHE_LIMIT:
                FROM_CONST_CACHE[key] = sv

            return sv

        return SymbolicValue(
            _name=str(value),
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_path=Z3_FALSE,
        )

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

        return val, path_constraint

    def __add__(self, other: SymbolicValue) -> SymbolicValue:
        return SymbolicValue(
            _name=f"({self._name}+{other._name})",
            z3_int=self.z3_int + other.z3_int,
            is_int=z3.And(self.is_int, other.is_int),
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    def __sub__(self, other: SymbolicValue) -> SymbolicValue:
        return SymbolicValue(
            _name=f"({self._name}-{other._name})",
            z3_int=self.z3_int - other.z3_int,
            is_int=z3.And(self.is_int, other.is_int),
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    def __mul__(self, other: SymbolicValue) -> SymbolicValue:
        return SymbolicValue(
            _name=f"({self._name}*{other._name})",
            z3_int=self.z3_int * other.z3_int,
            is_int=z3.And(self.is_int, other.is_int),
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    def __neg__(self) -> SymbolicValue:
        return SymbolicValue(
            _name=f"(-{self._name})",
            z3_int=-self.z3_int,
            is_int=self.is_int,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            taint_labels=self.taint_labels,
        )

    def __mod__(self, other: SymbolicValue) -> SymbolicValue:
        return SymbolicValue(
            _name=f"({self._name}%{other._name})",
            z3_int=self.z3_int % other.z3_int,
            is_int=z3.And(self.is_int, other.is_int),
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    def __floordiv__(self, other: SymbolicValue) -> SymbolicValue:
        return SymbolicValue(
            _name=f"({self._name}//{other._name})",
            z3_int=self.z3_int / other.z3_int,
            is_int=z3.And(self.is_int, other.is_int),
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_path=Z3_FALSE,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    def __truediv__(self, other: SymbolicValue) -> SymbolicValue:
        is_path = self.is_path

        return SymbolicValue(
            _name=f"({self._name}/{other._name})",
            z3_int=self.z3_int / other.z3_int,
            is_int=z3.And(self.is_int, other.is_int),
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_path=is_path,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    def __pow__(self, other: SymbolicValue) -> SymbolicValue:
        taint = _merge_taint(self.taint_labels, other.taint_labels)

        return SymbolicValue(
            _name=f"({self._name}**{other._name})",
            z3_int=self.z3_int**other.z3_int,
            is_int=z3.And(self.is_int, other.is_int),
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_path=Z3_FALSE,
            taint_labels=taint if taint else None,
        )

    def __eq__(self, other: object) -> SymbolicValue:
        if not isinstance(other, SymbolicValue):
            other = SymbolicValue.from_const(other)

        int_eq = z3.And(self.is_int, other.is_int, self.z3_int == other.z3_int)

        bool_eq = z3.And(self.is_bool, other.is_bool, self.z3_bool == other.z3_bool)

        none_eq = z3.And(self.is_none, other.is_none)

        path_eq = z3.And(self.is_path, other.is_path, self.z3_int == other.z3_int)

        result_bool = z3.Or(int_eq, bool_eq, none_eq, path_eq)

        return SymbolicValue(
            _name=f"({self._name}=={getattr(other, '_name', str(other))})",
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=result_bool,
            is_bool=Z3_TRUE,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    def __ne__(self, other: object) -> SymbolicValue:
        if not isinstance(other, SymbolicValue):
            other = SymbolicValue.from_const(other)

        eq = self.__eq__(other)

        return SymbolicValue(
            _name=f"({self._name}!={getattr(other, '_name', str(other))})",
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=z3.Not(eq.z3_bool),
            is_bool=Z3_TRUE,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    def __lt__(self, other: Any) -> SymbolicValue:
        if not isinstance(other, SymbolicValue):
            other = SymbolicValue.from_const(other)

        cmp = self.z3_int < other.z3_int

        return SymbolicValue(
            _name=f"({self._name}<{other.name})",
            z3_int=z3.If(cmp, z3.IntVal(1), Z3_ZERO),
            is_int=Z3_TRUE,
            z3_bool=cmp,
            is_bool=Z3_TRUE,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    def __le__(self, other: Any) -> SymbolicValue:
        if not isinstance(other, SymbolicValue):
            other = SymbolicValue.from_const(other)

        cmp = self.z3_int <= other.z3_int

        return SymbolicValue(
            _name=f"({self._name}<={other.name})",
            z3_int=z3.If(cmp, z3.IntVal(1), Z3_ZERO),
            is_int=Z3_TRUE,
            z3_bool=cmp,
            is_bool=Z3_TRUE,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    def __gt__(self, other: Any) -> SymbolicValue:
        if not isinstance(other, SymbolicValue):
            other = SymbolicValue.from_const(other)

        cmp = self.z3_int > other.z3_int

        return SymbolicValue(
            _name=f"({self._name}>{other.name})",
            z3_int=z3.If(cmp, z3.IntVal(1), Z3_ZERO),
            is_int=Z3_TRUE,
            z3_bool=cmp,
            is_bool=Z3_TRUE,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    def __ge__(self, other: Any) -> SymbolicValue:
        if not isinstance(other, SymbolicValue):
            other = SymbolicValue.from_const(other)

        cmp = self.z3_int >= other.z3_int

        return SymbolicValue(
            _name=f"({self._name}>={other.name})",
            z3_int=z3.If(cmp, z3.IntVal(1), Z3_ZERO),
            is_int=Z3_TRUE,
            z3_bool=cmp,
            is_bool=Z3_TRUE,
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    def __and__(self, other: SymbolicValue) -> SymbolicValue:
        return SymbolicValue(
            _name=f"({self._name}&{other._name})",
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=z3.And(self.z3_bool, other.z3_bool),
            is_bool=z3.And(self.is_bool, other.is_bool),
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    def __or__(self, other: SymbolicValue) -> SymbolicValue:
        return SymbolicValue(
            _name=f"({self._name}|{other._name})",
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=z3.Or(self.z3_bool, other.z3_bool),
            is_bool=z3.And(self.is_bool, other.is_bool),
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    def __xor__(self, other: SymbolicValue) -> SymbolicValue:
        return SymbolicValue(
            _name=f"({self._name}^{other._name})",
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=z3.Xor(self.z3_bool, other.z3_bool),
            is_bool=z3.And(self.is_bool, other.is_bool),
            taint_labels=_merge_taint(self.taint_labels, other.taint_labels),
        )

    def __invert__(self) -> SymbolicValue:
        return SymbolicValue(
            _name=f"(~{self._name})",
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=z3.Not(self.z3_bool),
            is_bool=self.is_bool,
            taint_labels=self.taint_labels,
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
        )

    def __repr__(self) -> str:
        return f"SymbolicValue({self._name})"


from pysymex.core.types_containers import (
    SymbolicDict,
    SymbolicList,
    SymbolicObject,
    SymbolicString,
)

AnySymbolic = Union[
    SymbolicValue, SymbolicString, SymbolicList, SymbolicDict, SymbolicNone, SymbolicObject
]
