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

from pysymex.core.constants import Z3_EMPTY_STRING, Z3_FALSE, Z3_ONE, Z3_TRUE, Z3_ZERO
from pysymex.core.solver.constraints.hashing import get_int_val, get_string_val
from pysymex.core.types.base import SymbolicType
from pysymex.core.types.scalars.values import (
    STRING_CONST_CACHE,
    STRING_CONST_CACHE_LIMIT,
    STRING_CONST_CACHE_LOCK,
    AnySymbolic,
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
        default_factory=_character_count_bounds_factory, repr=False, compare=False
    )
    _concrete_length: int | None = field(default=None, repr=False, compare=False)
    _delegated_len_cache: z3.ArithRef | None = field(
        default=None, init=False, repr=False, compare=False
    )
    _truthy_cache: z3.BoolRef | None = field(default=None, init=False, repr=False, compare=False)
    _falsy_cache: z3.BoolRef | None = field(default=None, init=False, repr=False, compare=False)
    _hash_cache: int | None = field(default=None, init=False, repr=False, compare=False)

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

    def with_binary_integer_source(self, source: z3.ArithRef) -> SymbolicString:
        """Retain the integer expression used to produce a ``bin(value)`` result."""
        self._binary_integer_source = source
        return self

    def with_character_count_upper_bound(self, character: str, upper_bound: int) -> SymbolicString:
        """Retain a sound upper bound for one-character ``str.count`` results."""
        if len(character) != 1:
            raise ValueError("character count metadata requires one character")
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

    def __add__(self, other: object) -> SymbolicString:
        """Return string concatenation or raise for a definitely non-string operand."""
        if not isinstance(other, (SymbolicString, str)):
            raise TypeError(f"can only concatenate str (not '{type(other).__name__}') to str")
        other_z3 = other.z3_str if isinstance(other, SymbolicString) else get_string_val(other)
        other_len = other.z3_len if isinstance(other, SymbolicString) else get_int_val(len(other))
        return SymbolicString(
            _z3_str=z3.Concat(self.z3_str, other_z3),
            _z3_len=self.z3_len + other_len,
            _name=f"({self._name}+{getattr(other, 'name', str(other))})",
        )

    @staticmethod
    def symbolic(name: str) -> tuple[SymbolicString, z3.BoolRef]:
        """Create a unified symbolic value constrained to the string branch.

        Notes:
            Callers must add the returned type constraint where this value
            participates in path semantics.
        """
        sv, constraint = SymbolicValue.symbolic(name)
        str_constraint = z3.And(constraint, sv.is_str)
        return SymbolicString(_name=name, _unified=sv), str_constraint

    @staticmethod
    def from_const(value: str) -> SymbolicString:
        """Create or reuse the bounded cached representation of a concrete string."""
        cached = STRING_CONST_CACHE.get(value)
        if isinstance(cached, SymbolicString):
            return cached
        z3_str = get_string_val(value)
        z3_len = get_int_val(len(value))
        sv = SymbolicString(
            _z3_str=z3_str,
            _z3_len=z3_len,
            _name=repr(value),
            _concrete_length=len(value),
        )
        with STRING_CONST_CACHE_LOCK:
            if len(STRING_CONST_CACHE) < STRING_CONST_CACHE_LIMIT:
                STRING_CONST_CACHE[value] = sv
        return sv

    def __repr__(self) -> str:
        """Return the diagnostic representation for this string carrier."""
        return f"SymbolicString(name={self._name})"

    def length(self) -> z3.ArithRef:
        """Return the retained or delegated string length expression."""
        return self.z3_len

    def contains(self, sub: object) -> SymbolicValue:
        """Return a Boolean-valued carrier for substring containment."""
        if not isinstance(sub, (SymbolicString, str)):
            raise TypeError("must be str or SymbolicString")
        sub_z3 = sub.z3_str if isinstance(sub, SymbolicString) else get_string_val(sub)
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
            raise TypeError("must be str or SymbolicString")
        prefix_z3 = prefix.z3_str if isinstance(prefix, SymbolicString) else get_string_val(prefix)
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
            raise TypeError("must be str or SymbolicString")
        suffix_z3 = suffix.z3_str if isinstance(suffix, SymbolicString) else get_string_val(suffix)
        cond = z3.SuffixOf(suffix_z3, self.z3_str)
        return SymbolicValue(
            _name=f"{self.name}.endswith(...)",
            z3_int=z3.If(cond, Z3_ONE, Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=cond,
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )

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
            s = get_int_val(start_raw)
        elif isinstance(start_raw, z3.ArithRef):
            s = start_raw
        else:
            raise TypeError("substring start must be an integer or symbolic integer")
        if isinstance(end_raw, int):
            e = get_int_val(end_raw)
        elif isinstance(end_raw, z3.ArithRef):
            e = end_raw
        else:
            raise TypeError("substring end must be an integer or symbolic integer")
        len_s = e - s
        sub = z3.If(
            z3.And(s >= 0, len_s >= 0), z3.SubString(self.z3_str, s, len_s), Z3_EMPTY_STRING
        )
        return SymbolicString(
            _z3_str=sub,
            _z3_len=z3.Length(sub),
            _name=f"({self._name}[{s}:{e}])",
        )

    def conditional_merge(self, other: AnySymbolic, condition: z3.BoolRef) -> SymbolicValue:
        """Delegate branch selection through the unified scalar representation."""
        return SymbolicValue.from_specialized(self).conditional_merge(other, condition)
