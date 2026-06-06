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

"""Int-valued symbolic dictionary storage with optional concrete tracking."""

from __future__ import annotations

import dataclasses
from collections.abc import Hashable
from dataclasses import dataclass, field
from typing import cast

import z3

from pysymex.core.types.containers.helpers import known_length_truthiness, storage_int_expr
from pysymex.core.types.containers.dict_merge import SymbolicDictMergeMixin
from pysymex.core.types.numeric.int import SymbolicInt
from pysymex.core.constants import Z3_FALSE
from pysymex.core.constants import Z3_TRUE
from pysymex.core.constants import Z3_ZERO
from pysymex.core.solver.constraints.hashing import get_string_val
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.base import SymbolicType
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.core.types.scalars.values import fresh_name

_UNRESOLVED_KEY = object()


def _concrete_lookup_key(key: object) -> object:
    """Return a concrete dictionary key or the unresolved-key sentinel."""
    if isinstance(key, SymbolicString):
        if z3.is_string_value(key.z3_str):
            return key.z3_str.as_string()
        return _UNRESOLVED_KEY
    if isinstance(key, SymbolicInt):
        if z3.is_int_value(key.z3_int):
            return key.z3_int.as_long()
        return _UNRESOLVED_KEY
    if isinstance(key, SymbolicValue):
        if key.value is not None:
            return key.value
        if z3.is_true(key.is_none):
            return None
        if not z3.is_false(key.is_none) and z3.is_true(z3.simplify(key.is_none)):
            return None
        is_int = z3.is_true(key.is_int) or (
            not z3.is_false(key.is_int) and z3.is_true(z3.simplify(key.is_int))
        )
        if is_int and z3.is_int_value(key.z3_int):
            return key.z3_int.as_long()
        is_str = z3.is_true(key.is_str) or (
            not z3.is_false(key.is_str) and z3.is_true(z3.simplify(key.is_str))
        )
        if is_str and z3.is_string_value(key.z3_str):
            return key.z3_str.as_string()
        return _UNRESOLVED_KEY
    return key


def _symbolic_key_equals_concrete(key: object, concrete_key: object) -> z3.BoolRef | None:
    """Return a symbolic equality predicate against a supported concrete key."""
    if isinstance(key, SymbolicString):
        if isinstance(concrete_key, str):
            return key.z3_str == get_string_val(concrete_key)
        return Z3_FALSE

    if not isinstance(key, SymbolicValue):
        return None

    if concrete_key is None:
        return key.is_none
    if isinstance(concrete_key, bool):
        concrete_bool = Z3_TRUE if concrete_key else Z3_FALSE
        return z3.Or(
            z3.And(key.is_bool, key.z3_bool == concrete_bool),
            z3.And(key.is_int, key.z3_int == int(concrete_key)),
        )
    if isinstance(concrete_key, int):
        return z3.And(key.is_int, key.z3_int == concrete_key)
    if isinstance(concrete_key, str):
        return z3.And(key.is_str, key.z3_str == get_string_val(concrete_key))
    return None


def _symbolic_storage_key(key: object) -> SymbolicString:
    """Return the Z3 string key used by dictionary array storage."""
    if isinstance(key, SymbolicString):
        return key
    concrete_key = _concrete_lookup_key(key)
    storage_key = concrete_key if concrete_key is not _UNRESOLVED_KEY else key
    return SymbolicString.from_const(str(storage_key))


@dataclass
class SymbolicDict(SymbolicDictMergeMixin, SymbolicType):
    """Int-valued Z3-array dictionary with optional retained concrete mapping."""

    _name: str
    z3_array: z3.ArrayRef
    known_keys: z3.ArrayRef
    z3_len: z3.ArithRef
    _h_active: bool = field(default=False)
    _concrete_items: dict[object, object] | None = field(default=None, compare=False)
    _has_default_factory: bool = field(default=False, compare=False)

    def __post_init__(self) -> None:
        """Mark receiver-like dict names for heuristic tracking."""
        if self._name:
            ln = self._name.lower()
            if ln in ("self", "cls") or ln.startswith(("self_", "cls_")):
                self._h_active = True

    __hash__ = object.__hash__

    @property
    def name(self) -> str:
        """Return the diagnostic name."""
        return self._name

    @property
    def is_dict(self) -> z3.BoolRef:
        """Return the definite dict-type marker."""
        return Z3_TRUE

    @property
    def concrete_items(self) -> dict[object, object] | None:
        """Return a copy of retained concrete items when this dict is exact."""
        if self._concrete_items is None:
            return None
        return dict(self._concrete_items)

    def to_z3(self) -> z3.ExprRef:
        """Return the Z3 value array."""
        return self.z3_array

    def copy(self) -> SymbolicDict:
        """Return a shallow copy of this symbolic dict."""
        concrete_items = dict(self._concrete_items) if self._concrete_items is not None else None
        return dataclasses.replace(self, _concrete_items=concrete_items)

    def clear(self) -> SymbolicDict:
        """Return an empty dictionary preserving the default-factory policy."""
        return SymbolicDict(
            _name=f"{self._name}.clear()",
            z3_array=self.z3_array,
            known_keys=z3.K(z3.StringSort(), Z3_FALSE),
            z3_len=Z3_ZERO,
            _concrete_items={},
            _has_default_factory=self._has_default_factory,
        )

    def could_be_truthy(self) -> z3.BoolRef:
        """Nonempty predicate."""
        if self._concrete_items is not None:
            return Z3_TRUE if self._concrete_items else Z3_FALSE
        return known_length_truthiness(self.z3_len, truthy=True)

    def could_be_falsy(self) -> z3.BoolRef:
        """Empty predicate."""
        if self._concrete_items is not None:
            return Z3_FALSE if self._concrete_items else Z3_TRUE
        return known_length_truthiness(self.z3_len, truthy=False)

    def hash_value(self) -> int:
        """Return a structural hash over Z3 storage and length expressions."""
        return (self.z3_array.hash() * 31) ^ (self.known_keys.hash() * 1000003) ^ self.z3_len.hash()

    @staticmethod
    def symbolic(name: str) -> tuple[SymbolicDict, z3.BoolRef]:
        """Create a symbolic dict and its nonnegative-length constraint."""
        z3_array = z3.Array(f"{name}_dict", z3.StringSort(), z3.IntSort())
        # Use an Array as a Set (String -> Bool)
        known_keys = z3.Array(f"{name}_keys", z3.StringSort(), z3.BoolSort())
        z3_len = z3.Int(f"{name}_len")
        constraint = z3_len >= 0
        return SymbolicDict(name, z3_array, known_keys, z3_len), constraint

    @staticmethod
    def symbolic_int_dict(name: str | None = None) -> SymbolicDict:
        """Create a symbolic dict while discarding its length constraint."""
        dict_name = name or fresh_name("dict")
        symbolic_dict, _ = SymbolicDict.symbolic(dict_name)
        return symbolic_dict

    @staticmethod
    def empty(name: str = "empty_dict") -> SymbolicDict:
        """Create an empty symbolic dict."""
        z3_array = z3.Array(f"{name}_dict", z3.StringSort(), z3.IntSort())
        known_keys = z3.K(z3.StringSort(), Z3_FALSE)
        z3_len = Z3_ZERO
        return SymbolicDict(name, z3_array, known_keys, z3_len)

    @staticmethod
    def from_const(values: dict[object, object]) -> SymbolicDict:
        """Create a symbolic dict initialized from a concrete mapping."""
        result = dataclasses.replace(
            SymbolicDict.empty(name=fresh_name("const_dict")),
            _concrete_items={},
        )
        for key, value in values.items():
            result = result.__setitem__(key, value)
        return result

    def concrete_key_presence_condition(self, key: object) -> z3.BoolRef | None:
        """Return a path predicate for membership in concrete-backed dictionaries."""
        value_conditions = self.concrete_value_conditions_for_key(key)
        if value_conditions is None:
            return None
        if not value_conditions:
            return Z3_FALSE
        return z3.simplify(z3.Or(*(condition for condition, _value in value_conditions)))

    def concrete_value_conditions_for_key(
        self, key: object
    ) -> tuple[tuple[z3.BoolRef, object], ...] | None:
        """Return retained values paired with path predicates for a lookup key."""
        concrete_items = self._concrete_items
        if concrete_items is None:
            return None

        concrete_key = _concrete_lookup_key(key)
        if concrete_key is not _UNRESOLVED_KEY:
            if not isinstance(concrete_key, Hashable):
                return None
            if concrete_key not in concrete_items:
                return ()
            return ((Z3_TRUE, concrete_items[concrete_key]),)

        value_conditions: list[tuple[z3.BoolRef, object]] = []
        for candidate, value in concrete_items.items():
            condition = _symbolic_key_equals_concrete(key, candidate)
            if condition is not None:
                value_conditions.append((z3.simplify(condition), value))
        if not value_conditions:
            return None
        return tuple(value_conditions)

    def concrete_value_for_key(self, key: object) -> tuple[bool, object | None]:
        """Return whether a concrete-backed value is known and the value itself."""
        concrete_items = self._concrete_items
        if concrete_items is None:
            return False, None
        concrete_key = _concrete_lookup_key(key)
        if concrete_key is _UNRESOLVED_KEY or not isinstance(concrete_key, Hashable):
            return False, None
        if concrete_key not in concrete_items:
            return False, None
        return True, concrete_items[concrete_key]

    def __getitem__(self, key: object) -> tuple[SymbolicValue, z3.BoolRef]:
        """Return an Int-valued lookup and known-key presence predicate."""
        sym_key = _symbolic_storage_key(key)
        elem = z3.Select(self.z3_array, sym_key.z3_str)

        presence_check = z3.Select(self.known_keys, sym_key.z3_str)
        if self._has_default_factory:
            elem = z3.If(presence_check, elem, Z3_ZERO)
            presence_check = Z3_TRUE
        val = SymbolicValue(
            _name=f"{self._name}[{sym_key.name}]",
            z3_int=cast("z3.ArithRef", elem),
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
        return val, cast(z3.BoolRef, presence_check)

    def __setitem__(self, key: object, value: object) -> SymbolicDict:
        """Return an updated dict, dropping concrete tracking for unresolved keys."""
        sym_key = _symbolic_storage_key(key)
        sym_value = value if isinstance(value, SymbolicValue) else SymbolicValue.from_const(value)
        new_array = z3.Store(
            self.z3_array,
            sym_key.z3_str,
            storage_int_expr(sym_value.z3_int, f"{self._name}value"),
        )

        is_existing_key = z3.Select(self.known_keys, sym_key.z3_str)
        new_keys = z3.Store(self.known_keys, sym_key.z3_str, Z3_TRUE)

        new_len = z3.If(is_existing_key, self.z3_len, self.z3_len + 1)
        new_concrete = dict(self._concrete_items) if self._concrete_items is not None else None
        concrete_key = _concrete_lookup_key(key)
        if (
            new_concrete is not None
            and concrete_key is not _UNRESOLVED_KEY
            and isinstance(concrete_key, Hashable)
        ):
            new_concrete[concrete_key] = value
        else:
            new_concrete = None

        return SymbolicDict(
            _name=f"{self._name}[{sym_key.name}]={sym_value.name}",
            z3_array=new_array,
            known_keys=new_keys,
            z3_len=new_len,
            _concrete_items=new_concrete,
            _has_default_factory=self._has_default_factory,
        )

    def __delitem__(self, key: object) -> SymbolicDict:
        """Return a deletion view, dropping concrete tracking for unresolved keys."""
        sym_key = _symbolic_storage_key(key)

        is_existing_key = z3.Select(self.known_keys, sym_key.z3_str)
        new_keys = z3.Store(self.known_keys, sym_key.z3_str, Z3_FALSE)

        new_len = z3.If(is_existing_key, self.z3_len - 1, self.z3_len)

        new_concrete = dict(self._concrete_items) if self._concrete_items is not None else None
        concrete_key = _concrete_lookup_key(key)
        if (
            new_concrete is not None
            and concrete_key is not _UNRESOLVED_KEY
            and isinstance(concrete_key, Hashable)
        ):
            if concrete_key in new_concrete:
                del new_concrete[concrete_key]
        elif new_concrete is not None:
            new_concrete = None

        return SymbolicDict(
            _name=f"del {self._name}[{sym_key.name}]",
            z3_array=self.z3_array,
            known_keys=new_keys,
            z3_len=new_len,
            _concrete_items=new_concrete,
            _has_default_factory=self._has_default_factory,
        )

    def contains_key(self, key: SymbolicString) -> SymbolicValue:
        """Return a Boolean carrier selecting membership from ``known_keys``."""
        result = cast("z3.BoolRef", z3.Select(self.known_keys, key.z3_str))
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
        )

    def contains(self, key: SymbolicInt) -> z3.BoolRef:
        """Return the symbolic known-key membership condition for ``key``."""
        key_expr = z3.IntToStr(key.z3_int)
        selected = z3.Select(self.known_keys, key_expr)
        if isinstance(selected, z3.BoolRef):
            return selected
        return Z3_FALSE

    def __contains__(self, key: object) -> bool:
        """Return ``True`` only for definitely present concrete-backed keys."""
        presence = self.concrete_key_presence_condition(key)
        if presence is None:
            return False
        simplified = z3.simplify(presence)
        if z3.is_true(simplified):
            return True
        if z3.is_false(simplified):
            return False
        return False

    @property
    def length(self) -> SymbolicValue:
        """Return the symbolic dictionary length as a scalar carrier."""
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

    def __repr__(self) -> str:
        """Diagnostic repr."""
        return f"SymbolicDict({self._name})"
