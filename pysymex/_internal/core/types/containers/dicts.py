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
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.base import SymbolicType, fresh_name
from pysymex._internal.core.types.containers.dict.concrete import (
    concrete_key_presence,
    concrete_value,
    concrete_value_conditions,
    contains_concrete_key,
    copy_concrete_items,
)
from pysymex._internal.core.types.containers.dict.keys import symbolic_storage_key
from pysymex._internal.core.types.containers.dict.merge import SymbolicDictMergeMixin
from pysymex._internal.core.types.containers.dict.retention import (
    concrete_items_after_delete,
    concrete_items_after_set,
)
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.containers.storage_ops import ContainerStorageOps
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.types.numeric.int import SymbolicInt
    from pysymex._internal.core.types.scalars.strings import SymbolicString


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
    _value_type: str | None = field(default=None, compare=False)

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
        return copy_concrete_items(self._concrete_items)

    def to_z3(self) -> z3.ExprRef:
        """Return the Z3 value array."""
        return self.z3_array

    def set_value_type(self, type_name: str) -> None:
        """Set retained element type metadata for lowered collection operations."""
        self._value_type = type_name

    def set_runtime_type(self, type_name: str) -> None:
        """Set the runtime type label for dictionary-like carriers."""
        self._type = type_name

    @property
    def runtime_type(self) -> str | None:
        """Return the runtime type label for dictionary-like carriers."""
        return self._type

    def enable_default_factory(self) -> None:
        """Mark the dictionary as default-factory backed."""
        self._has_default_factory = True

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
            _value_type=self._value_type,
        )

    def could_be_truthy(self) -> z3.BoolRef:
        """Nonempty predicate."""
        if self._concrete_items is not None:
            return Z3_TRUE if self._concrete_items else Z3_FALSE
        return ContainerStorageOps.known_length_truthiness(self.z3_len, truthy=True)

    def could_be_falsy(self) -> z3.BoolRef:
        """Empty predicate."""
        if self._concrete_items is not None:
            return Z3_FALSE if self._concrete_items else Z3_TRUE
        return ContainerStorageOps.known_length_truthiness(self.z3_len, truthy=False)

    def hash_value(self) -> int:
        """Return a structural hash over Z3 storage and length expressions."""
        return (self.z3_array.hash() * 31) ^ (self.known_keys.hash() * 1000003) ^ self.z3_len.hash()

    def symbolic_length(self) -> z3.ArithRef:
        """Return the represented dictionary length."""
        return self.z3_len

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

    @staticmethod
    def from_const_named(name: str, values: dict[object, object]) -> SymbolicDict:
        """Create a concrete-backed symbolic dict with a stable diagnostic root."""
        result = dataclasses.replace(SymbolicDict.empty(name=name), _concrete_items={})
        for key, value in values.items():
            result = result.__setitem__(key, value)
        return dataclasses.replace(result, _name=name)

    def concrete_key_presence_condition(self, key: object) -> z3.BoolRef | None:
        """Return a path predicate for membership in concrete-backed dictionaries."""
        return concrete_key_presence(self._concrete_items, key)

    def concrete_value_conditions_for_key(
        self,
        key: object,
    ) -> tuple[tuple[z3.BoolRef, object], ...] | None:
        """Return retained values paired with path predicates for a lookup key."""
        return concrete_value_conditions(self._concrete_items, key)

    def concrete_value_for_key(self, key: object) -> tuple[bool, object | None]:
        """Return whether a concrete-backed value is known and the value itself."""
        return concrete_value(self._concrete_items, key)

    def __getitem__(self, key: object) -> tuple[SymbolicValue, z3.BoolRef]:
        """Return an Int-valued lookup and known-key presence predicate."""
        sym_key = symbolic_storage_key(key)
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
        return val, cast("z3.BoolRef", presence_check)

    def __setitem__(self, key: object, value: object) -> SymbolicDict:
        """Return an updated dict, dropping concrete tracking for unresolved keys."""
        sym_key = symbolic_storage_key(key)
        sym_value = value if isinstance(value, SymbolicValue) else SymbolicValue.from_const(value)
        new_array = z3.Store(
            self.z3_array,
            sym_key.z3_str,
            ContainerStorageOps.storage_int_expr(sym_value.z3_int, f"{self._name}value"),
        )

        is_existing_key = z3.Select(self.known_keys, sym_key.z3_str)
        new_keys = z3.Store(self.known_keys, sym_key.z3_str, Z3_TRUE)

        new_concrete = concrete_items_after_set(
            self._concrete_items,
            key,
            value,
            parent_name=f"{self._name}[*]",
        )
        new_len = (
            ConstraintValues.int(len(new_concrete))
            if new_concrete is not None
            else z3.If(is_existing_key, self.z3_len, self.z3_len + 1)
        )

        return SymbolicDict(
            _name=f"{self._name}[{sym_key.name}]={sym_value.name}",
            z3_array=new_array,
            known_keys=new_keys,
            z3_len=new_len,
            _concrete_items=new_concrete,
            _has_default_factory=self._has_default_factory,
            _value_type=self._value_type,
        )

    def __delitem__(self, key: object) -> SymbolicDict:
        """Return a deletion view, dropping concrete tracking for unresolved keys."""
        sym_key = symbolic_storage_key(key)

        is_existing_key = z3.Select(self.known_keys, sym_key.z3_str)
        new_keys = z3.Store(self.known_keys, sym_key.z3_str, Z3_FALSE)

        new_concrete = concrete_items_after_delete(self._concrete_items, key)
        new_len = (
            ConstraintValues.int(len(new_concrete))
            if new_concrete is not None
            else z3.If(is_existing_key, self.z3_len - 1, self.z3_len)
        )

        return SymbolicDict(
            _name=f"del {self._name}[{sym_key.name}]",
            z3_array=self.z3_array,
            known_keys=new_keys,
            z3_len=new_len,
            _concrete_items=new_concrete,
            _has_default_factory=self._has_default_factory,
            _value_type=self._value_type,
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
        return contains_concrete_key(self._concrete_items, key)

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

    @staticmethod
    def resolve(arg: object, state: VMState | None = None) -> SymbolicDict | None:
        """Return a dict carrier directly or through a heap object handle."""
        if isinstance(arg, SymbolicDict):
            return arg
        if state is not None and isinstance(arg, SymbolicObject):
            value = state.memory.get(arg.address)
            if isinstance(value, SymbolicDict):
                return value
        return None
