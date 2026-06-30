# pysymex: python symbolic execution & formal verification
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

"""Z3 sequence-backed string carrier and string-specific operations."""

from __future__ import annotations

from dataclasses import dataclass, field

import z3

from pysymex._internal.core.constants import Z3_EMPTY_STRING, Z3_FALSE, Z3_ONE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.base import SymbolicType
from pysymex._internal.core.types.containers.slices import (
    normalize_unit_slice_bound,
    unit_slice_extract_length,
    unit_slice_step_is_supported,
)
from pysymex._internal.core.types.scalars.value.composition import (
    bind_symbolic_value_factory_classes,
)
from pysymex._internal.core.types.scalars.value.scalar_ops import (
    STRING_CONST_CACHE,
    STRING_CONST_CACHE_LIMIT,
    STRING_CONST_CACHE_LOCK,
    bind_scalar_value_classes,
)
from pysymex._internal.core.types.scalars.values import (
    SymbolicValue,
)


def _character_count_bounds_factory() -> dict[str, int]:
    """Return the mutable metadata map for retained ``str.count`` facts."""
    return {}


@dataclass(slots=True)
class SymbolicString(SymbolicType):
    """String value represented by a Z3 string sequence and length expression.

    A symbolic string created from the unified scalar carrier delegates
    truthiness and storage access to that carrier.
    """

    _z3_str: z3.SeqRef = field(default_factory=lambda: Z3_EMPTY_STRING)
    _z3_len: z3.ArithRef = field(default_factory=lambda: Z3_ZERO)
    _name: str = ""
    _unified: SymbolicValue | None = field(default=None, repr=False, compare=False)
    _binary_integer_source: z3.ArithRef | None = field(default=None, repr=False, compare=False)
    _character_count_upper_bounds: dict[str, int] = field(
        default_factory=_character_count_bounds_factory,
        repr=False,
        compare=False,
    )
    _concrete_length: int | None = field(default=None, repr=False, compare=False)
    _delegated_len_cache: z3.ArithRef | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )
    _truthy_cache: z3.BoolRef | None = field(default=None, init=False, repr=False, compare=False)
    _falsy_cache: z3.BoolRef | None = field(default=None, init=False, repr=False, compare=False)
    _hash_cache: int | None = field(default=None, init=False, repr=False, compare=False)

    def __copy__(self) -> SymbolicString:
        """Return an isolated string carrier over immutable/cached payload channels."""
        clone = type(self).__new__(type(self))
        clone._z3_str = self._z3_str
        clone._z3_len = self._z3_len
        clone._name = self._name
        clone._unified = None
        clone._binary_integer_source = self._binary_integer_source
        clone._character_count_upper_bounds = {}
        clone._concrete_length = self._concrete_length
        clone._delegated_len_cache = None
        clone._truthy_cache = self._truthy_cache
        clone._falsy_cache = self._falsy_cache
        clone._hash_cache = self._hash_cache
        return clone

    @property
    def z3_str(self) -> z3.SeqRef:
        """Return the retained or delegated Z3 string expression."""
        if self._unified is not None:
            return self._unified.z3_str
        return self._z3_str

    @property
    def z3_len(self) -> z3.ArithRef:
        """Return the retained or derived string-length expression."""
        if self._unified is not None:
            cached = self._delegated_len_cache
            if cached is None:
                cached = z3.Length(self._unified.z3_str)
                self._delegated_len_cache = cached
            return cached
        return self._z3_len

    @property
    def name(self) -> str:
        """Return the diagnostic name for this symbolic string."""
        return self._name

    @property
    def type_tag(self) -> str:
        """Return the runtime-type label for this carrier."""
        return "str"

    @property
    def binary_integer_source(self) -> z3.ArithRef | None:
        """Return the integer expression used to produce ``bin(value)``, if retained."""
        return self._binary_integer_source

    @property
    def concrete_value(self) -> str | None:
        """Return the exact retained string, when this carrier is concrete."""
        if self._unified is not None or self._concrete_length is None:
            return None
        if z3.is_string_value(self._z3_str):
            return self._z3_str.as_string()
        return None

    @property
    def concrete_length(self) -> int | None:
        """Return the exact retained string length without consulting Z3."""
        if self._unified is not None:
            return None
        return self._concrete_length

    @property
    def unified_value(self) -> SymbolicValue | None:
        """Return the scalar carrier backing this string, when it is a unified view."""
        return self._unified

    def with_binary_integer_source(self, source: z3.ArithRef) -> SymbolicString:
        """Retain the integer expression used to produce a ``bin(value)`` result."""
        self._binary_integer_source = source
        return self

    def with_character_count_upper_bound(self, character: str, upper_bound: int) -> SymbolicString:
        """Retain a sound upper bound for one-character ``str.count`` results."""
        if len(character) != 1:
            msg = "character count metadata requires one character"
            raise ValueError(msg)
        existing = self._character_count_upper_bounds.get(character)
        if existing is None or upper_bound < existing:
            self._character_count_upper_bounds[character] = upper_bound
        return self

    def character_count_upper_bound(self, character: str) -> int | None:
        """Return a retained upper bound for ``self.count(character)``, if known."""
        return self._character_count_upper_bounds.get(character)

    @property
    def is_str(self) -> z3.BoolRef:
        """Return the definite string-type marker for this carrier."""
        return Z3_TRUE

    def to_z3(self) -> z3.ExprRef:
        """Return the represented Z3 string expression."""
        return self.z3_str

    def could_be_truthy(self) -> z3.BoolRef:
        """Return the delegated or positive-length truth predicate."""
        cached = self._truthy_cache
        if cached is not None:
            return cached
        if self._concrete_length is not None:
            cached = Z3_TRUE if self._concrete_length > 0 else Z3_FALSE
        elif self._unified is not None:
            cached = self._unified.could_be_truthy()
        else:
            cached = self.z3_len > 0
        self._truthy_cache = cached
        return cached

    def could_be_falsy(self) -> z3.BoolRef:
        """Return the delegated or zero-length falsity predicate."""
        cached = self._falsy_cache
        if cached is not None:
            return cached
        if self._concrete_length is not None:
            cached = Z3_FALSE if self._concrete_length > 0 else Z3_TRUE
        elif self._unified is not None:
            cached = self._unified.could_be_falsy()
        else:
            cached = self.z3_len == 0
        self._falsy_cache = cached
        return cached

    def hash_value(self) -> int:
        """Return the unified-value hash or string/length structural hash."""
        if self._unified is not None:
            return self._unified.hash_value()
        cached = self._hash_cache
        if cached is None:
            cached = self.z3_str.hash() ^ self.z3_len.hash()
            self._hash_cache = cached
        return cached

    def symbolic_length(self) -> z3.ArithRef:
        """Return the represented string length."""
        return self.z3_len

    def __add__(self, other: object) -> SymbolicString:
        """Return string concatenation or raise for a definitely non-string operand."""
        if not isinstance(other, (SymbolicString, str)):
            msg = f"can only concatenate str (not '{type(other).__name__}') to str"
            raise TypeError(msg)
        other_z3 = (
            other.z3_str if isinstance(other, SymbolicString) else ConstraintValues.string(other)
        )
        other_len = (
            other.z3_len if isinstance(other, SymbolicString) else ConstraintValues.int(len(other))
        )
        return SymbolicString(
            _z3_str=z3.Concat(self.z3_str, other_z3),
            _z3_len=self.z3_len + other_len,
            _name=f"({self._name}+{getattr(other, 'name', str(other))})",
        )

    def __radd__(self, other: object) -> SymbolicString:
        """Return string concatenation from left-hand operands."""
        if not isinstance(other, (SymbolicString, str)):
            msg = f"can only concatenate str (not '{type(other).__name__}') to str"
            raise TypeError(msg)
        other_z3 = (
            other.z3_str if isinstance(other, SymbolicString) else ConstraintValues.string(other)
        )
        other_len = (
            other.z3_len if isinstance(other, SymbolicString) else ConstraintValues.int(len(other))
        )
        return SymbolicString(
            _z3_str=z3.Concat(other_z3, self.z3_str),
            _z3_len=other_len + self.z3_len,
            _name=f"({getattr(other, 'name', str(other))}+{self._name})",
        )

    @staticmethod
    def symbolic(name: str) -> tuple[SymbolicString, z3.BoolRef]:
        """Create a direct symbolic string carrier.

        Definite ``str`` values do not need the full scalar type-union carrier;
        allocating one adds a large exactly-one-type constraint to every string
        benchmark path and makes pure string queries look like mixed scalar
        queries. Optional or dynamically typed values still use
        :class:`SymbolicValue` at their call sites.
        """
        z3_str = z3.String(name)
        return (
            SymbolicString(_z3_str=z3_str, _z3_len=z3.Length(z3_str), _name=name),
            Z3_TRUE,
        )

    @staticmethod
    def from_const(value: str) -> SymbolicString:
        """Create an isolated carrier over a bounded cached concrete representation."""
        cached = STRING_CONST_CACHE.get(value)
        if isinstance(cached, SymbolicString):
            return cached.__copy__()
        z3_str = ConstraintValues.string(value)
        z3_len = ConstraintValues.int(len(value))
        sv = SymbolicString(
            _z3_str=z3_str,
            _z3_len=z3_len,
            _name=repr(value),
            _concrete_length=len(value),
        )
        with STRING_CONST_CACHE_LOCK:
            if len(STRING_CONST_CACHE) < STRING_CONST_CACHE_LIMIT:
                STRING_CONST_CACHE[value] = sv.__copy__()
        return sv

    @staticmethod
    def resolve(arg: object) -> SymbolicString | None:
        """Return a definite string carrier without narrowing ambiguous values."""
        if isinstance(arg, SymbolicString):
            return arg
        if isinstance(arg, str):
            return SymbolicString.from_const(arg)
        if isinstance(arg, SymbolicValue) and z3.is_true(simplify_expr(arg.is_str)):
            return SymbolicString(_name=arg.name, _unified=arg)
        return None

    @staticmethod
    def concrete_literal(arg: object) -> str | None:
        """Return a concrete Python string when a symbolic carrier is exact."""
        if isinstance(arg, str):
            return arg
        if isinstance(arg, SymbolicString) and z3.is_string_value(arg.z3_str):
            return arg.z3_str.as_string()
        if isinstance(arg, SymbolicValue):
            if isinstance(arg.value, str):
                return arg.value
            if z3.is_true(simplify_expr(arg.is_str)) and z3.is_string_value(arg.z3_str):
                return arg.z3_str.as_string()
        return None

    def __repr__(self) -> str:
        """Return the diagnostic representation for this string carrier."""
        return f"SymbolicString(name={self._name})"

    def length(self) -> z3.ArithRef:
        """Return the retained or delegated string length expression."""
        return self.z3_len

    def contains(self, sub: object) -> SymbolicValue:
        """Return a Boolean-valued carrier for substring containment."""
        if not isinstance(sub, (SymbolicString, str)):
            msg = "must be str or SymbolicString"
            raise TypeError(msg)
        sub_z3 = sub.z3_str if isinstance(sub, SymbolicString) else ConstraintValues.string(sub)
        is_contained = z3.Contains(self.z3_str, sub_z3)
        return SymbolicValue(
            _name=f"({self.name} in {getattr(sub, 'name', str(sub))})",
            z3_int=z3.If(is_contained, Z3_ONE, Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=is_contained,
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )

    def startswith(self, prefix: object) -> SymbolicValue:
        """Return a Boolean-valued carrier for the prefix predicate."""
        if not isinstance(prefix, (SymbolicString, str)):
            msg = "must be str or SymbolicString"
            raise TypeError(msg)
        prefix_z3 = (
            prefix.z3_str if isinstance(prefix, SymbolicString) else ConstraintValues.string(prefix)
        )
        cond = z3.PrefixOf(prefix_z3, self.z3_str)
        return SymbolicValue(
            _name=f"{self.name}.startswith(...)",
            z3_int=z3.If(cond, Z3_ONE, Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=cond,
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )

    def endswith(self, suffix: object) -> SymbolicValue:
        """Return a Boolean-valued carrier for the suffix predicate."""
        if not isinstance(suffix, (SymbolicString, str)):
            msg = "must be str or SymbolicString"
            raise TypeError(msg)
        suffix_z3 = (
            suffix.z3_str if isinstance(suffix, SymbolicString) else ConstraintValues.string(suffix)
        )
        cond = z3.SuffixOf(suffix_z3, self.z3_str)
        return SymbolicValue(
            _name=f"{self.name}.endswith(...)",
            z3_int=z3.If(cond, Z3_ONE, Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=cond,
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )

    def strip_value(
        self,
        chars: object | None,
        name: str,
        *,
        side: str,
    ) -> tuple[SymbolicString, list[z3.BoolRef]]:
        """Return ``str.strip``/``lstrip``/``rstrip`` semantics and constraints."""
        concrete = self.concrete_value
        concrete_chars = SymbolicString.concrete_literal(chars) if chars is not None else None
        if concrete is not None and (chars is None or concrete_chars is not None):
            if side == "left":
                return SymbolicString.from_const(concrete.lstrip(concrete_chars)), []
            if side == "right":
                return SymbolicString.from_const(concrete.rstrip(concrete_chars)), []
            return SymbolicString.from_const(concrete.strip(concrete_chars)), []

        result, result_type = SymbolicString.symbolic(name)
        constraints = [
            result_type,
            result.z3_len <= self.z3_len,
            result.z3_len >= 0,
        ]
        if side == "left":
            constraints.append(z3.SuffixOf(result.z3_str, self.z3_str))
        elif side == "right":
            constraints.append(z3.PrefixOf(result.z3_str, self.z3_str))
        return result, constraints

    def remove_prefix(
        self,
        prefix: object,
        name: str,
    ) -> tuple[SymbolicString, list[z3.BoolRef]] | None:
        """Return ``str.removeprefix`` semantics and exact result constraints."""
        prefix_value = SymbolicString.resolve(prefix)
        if prefix_value is None:
            return None
        concrete = self.concrete_value
        prefix_concrete = prefix_value.concrete_value
        if concrete is not None and prefix_concrete is not None:
            return SymbolicString.from_const(concrete.removeprefix(prefix_concrete)), []

        result, result_type = SymbolicString.symbolic(name)
        is_prefix = z3.PrefixOf(prefix_value.z3_str, self.z3_str)
        stripped = z3.SubString(
            self.z3_str,
            prefix_value.z3_len,
            self.z3_len - prefix_value.z3_len,
        )
        constraints = [
            result_type,
            result.z3_len <= self.z3_len,
            result.z3_len >= 0,
            z3.Implies(is_prefix, result.z3_str == stripped),
            z3.Implies(z3.Not(is_prefix), result.z3_str == self.z3_str),
        ]
        return result, constraints

    def remove_suffix(
        self,
        suffix: object,
        name: str,
    ) -> tuple[SymbolicString, list[z3.BoolRef]] | None:
        """Return ``str.removesuffix`` semantics and exact result constraints."""
        suffix_value = SymbolicString.resolve(suffix)
        if suffix_value is None:
            return None
        concrete = self.concrete_value
        suffix_concrete = suffix_value.concrete_value
        if concrete is not None and suffix_concrete is not None:
            return SymbolicString.from_const(concrete.removesuffix(suffix_concrete)), []

        result, result_type = SymbolicString.symbolic(name)
        is_suffix = z3.SuffixOf(suffix_value.z3_str, self.z3_str)
        stripped = z3.SubString(
            self.z3_str,
            Z3_ZERO,
            self.z3_len - suffix_value.z3_len,
        )
        constraints = [
            result_type,
            result.z3_len <= self.z3_len,
            result.z3_len >= 0,
            z3.Implies(is_suffix, result.z3_str == stripped),
            z3.Implies(z3.Not(is_suffix), result.z3_str == self.z3_str),
        ]
        return result, constraints

    def substring(self, start: object, end: object) -> SymbolicString:
        """Return the encoded substring for integer or symbolic-integer bounds.

        Limitations:
            This method produces the empty string when ``start`` is negative
            or ``end - start`` is negative; it does not implement all Python
            slicing normalization behavior.
        """
        start_raw = getattr(start, "z3_int", start)
        end_raw = getattr(end, "z3_int", end)
        if isinstance(start_raw, int):
            s = ConstraintValues.int(start_raw)
        elif isinstance(start_raw, z3.ArithRef):
            s = start_raw
        else:
            msg = "substring start must be an integer or symbolic integer"
            raise TypeError(msg)
        if isinstance(end_raw, int):
            e = ConstraintValues.int(end_raw)
        elif isinstance(end_raw, z3.ArithRef):
            e = end_raw
        else:
            msg = "substring end must be an integer or symbolic integer"
            raise TypeError(msg)
        len_s = e - s
        sub = z3.If(
            z3.And(s >= 0, len_s >= 0),
            z3.SubString(self.z3_str, s, len_s),
            Z3_EMPTY_STRING,
        )
        return SymbolicString(
            _z3_str=sub,
            _z3_len=z3.Length(sub),
            _name=f"({self._name}[{s}:{e}])",
        )

    def slice_value(self, key: slice) -> SymbolicString | None:
        """Return exact CPython string-slice semantics when they can be encoded."""
        concrete = self.concrete_value
        if concrete is not None:
            return SymbolicString.from_const(concrete[key])

        if not unit_slice_step_is_supported(key.step):
            return None

        start = normalize_unit_slice_bound(key.start, self.z3_len, default_to_length=False)
        stop = normalize_unit_slice_bound(key.stop, self.z3_len, default_to_length=True)
        if start is None or stop is None:
            return None
        length = unit_slice_extract_length(start, stop)
        sub = z3.SubString(self.z3_str, start, length)
        return SymbolicString(
            _z3_str=sub,
            _z3_len=length,
            _name=f"({self._name}[{key.start}:{key.stop}:{key.step}])",
        )

    def conditional_merge(self, other: object, condition: z3.BoolRef) -> SymbolicValue:
        """Delegate branch selection through the unified scalar representation."""
        return SymbolicValue.from_specialized(self).conditional_merge(other, condition)


bind_scalar_value_classes(SymbolicValue, SymbolicString)
bind_symbolic_value_factory_classes(SymbolicValue, SymbolicString)
