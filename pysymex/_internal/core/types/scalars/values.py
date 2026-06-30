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

"""Union-like Z3-backed scalar carrier and its operation mixin bindings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.cache.control import register_process_cache_clearer
from pysymex._internal.core.constants import (
    Z3_EMPTY_BYTES,
    Z3_EMPTY_STRING,
    Z3_FALSE,
    Z3_FLOAT_ZERO,
    Z3_ZERO,
)
from pysymex._internal.core.types.affinity import (
    LENGTH_CHANNEL_AFFINITIES,
    AffinityKind,
    normalize_affinity,
    python_type_name_for_affinity,
)
from pysymex._internal.core.types.base import SymbolicType
from pysymex._internal.core.types.scalars.value.comparisons import (
    ValueComparisonMixin,
    bind_comparison_symbolic_value_class,
)
from pysymex._internal.core.types.scalars.value.composition import (
    SymbolicValueBitwiseMixin,
    SymbolicValueFactoryMixin,
    ValueArithmeticMixin,
    bind_symbolic_value_arithmetic_classes,
    bind_symbolic_value_bitwise_classes,
    bind_symbolic_value_factory_classes,
)
from pysymex._internal.core.types.scalars.value.scalar_ops import (
    FROM_CONST_CACHE,
    FROM_CONST_CACHE_LOCK,
    STRING_CONST_CACHE,
    STRING_CONST_CACHE_LOCK,
    SYMBOLIC_CACHE,
    ScalarValueOps,
)
from pysymex._internal.core.types.scalars.value.state import (
    ValueStateMixin,
    bind_state_symbolic_value_class,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pysymex._internal.core.types.containers.dicts import SymbolicDict

_FROM_CONST_CACHE_LOCK = FROM_CONST_CACHE_LOCK


def _clear_symbolic_scalar_value_caches() -> None:
    """Clear process-local scalar value construction caches."""
    SYMBOLIC_CACHE.clear()
    with _FROM_CONST_CACHE_LOCK:
        FROM_CONST_CACHE.clear()
    with STRING_CONST_CACHE_LOCK:
        STRING_CONST_CACHE.clear()


register_process_cache_clearer(
    "core.symbolic_scalar_value_caches",
    _clear_symbolic_scalar_value_caches,
)


@dataclass(slots=True, eq=False)
class SymbolicValue(
    ValueComparisonMixin,
    SymbolicValueBitwiseMixin,
    ValueArithmeticMixin,
    SymbolicValueFactoryMixin,
    ValueStateMixin,
    SymbolicType,
):
    """Union-like symbolic value with separate Z3 payload and type channels.

    Factories returning a companion constraint require callers to assert it.
    :meth:`to_z3` exposes only the integer channel.
    """

    z3_int: z3.ArithRef
    is_int: z3.BoolRef
    z3_bool: z3.BoolRef
    is_bool: z3.BoolRef
    z3_float: z3.FPRef = field(default=Z3_FLOAT_ZERO)
    is_float: z3.BoolRef = field(default=Z3_FALSE)
    z3_str: z3.SeqRef = field(default=Z3_EMPTY_STRING)
    is_str: z3.BoolRef = field(default=Z3_FALSE)
    z3_bytes: z3.SeqRef = field(default=Z3_EMPTY_BYTES)
    is_bytes: z3.BoolRef = field(default=Z3_FALSE)
    z3_addr: z3.ArithRef = field(default=Z3_ZERO)
    is_obj: z3.BoolRef = field(default=Z3_FALSE)

    z3_array: z3.ArrayRef | None = field(default=None)
    is_list: z3.BoolRef = field(default=Z3_FALSE)
    is_dict: z3.BoolRef = field(default=Z3_FALSE)
    is_tuple: z3.BoolRef = field(default=Z3_FALSE)
    is_set: z3.BoolRef = field(default=Z3_FALSE)

    _name: str = ""
    is_path: z3.BoolRef = field(default=Z3_FALSE)
    is_none: z3.BoolRef = field(default=Z3_FALSE)
    _constant_value: object = field(default=None, compare=False, repr=False)
    _bv_cache: z3.BitVecRef | None = field(default=None, init=False, repr=False, compare=False)

    affinity_type: str = field(default=AffinityKind.UNKNOWN, compare=False)
    _h_active: bool = field(default=False)

    def __post_init__(self) -> None:
        """Normalize diagnostic names and mark receiver-like values."""
        self.affinity_type = normalize_affinity(self.affinity_type)
        if self._name:
            if len(self._name) > 256:
                self._name = self._name[:128] + "..." + self._name[-125:]
            ln = self._name.lower()
            if ln in ("self", "cls") or ln.startswith(("self_", "cls_")):
                self._h_active = True

    min_val: int | float | None = field(default=None, compare=False)
    max_val: int | float | None = field(default=None, compare=False)

    @property
    def value(self) -> object:
        """Return the constant value of the symbolic value."""
        return self._constant_value

    _truthy_cache: z3.BoolRef | None = field(default=None, init=False, repr=False, compare=False)
    _falsy_cache: z3.BoolRef | None = field(default=None, init=False, repr=False, compare=False)

    model_name: str | None = field(default=None, init=False, repr=False, compare=False)
    _modeled_object: object | None = field(default=None, init=False, repr=False, compare=False)
    _type: str | None = field(default=None, init=False, repr=False, compare=False)
    _pysymex_bases_complete: bool = field(default=True, init=False, repr=False, compare=False)
    _pysymex_base_values: tuple[object, ...] = field(
        default_factory=tuple,
        init=False,
        repr=False,
        compare=False,
    )
    _pysymex_literal_enum_members: Mapping[str, object] | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )
    _pysymex_named_tuple_fields: tuple[str, ...] | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )
    _pysymex_dataclass_fields: (
        tuple[tuple[str, str | None, bool, object, str | None], ...] | None
    ) = field(default=None, init=False, repr=False, compare=False)
    _pysymex_dataclass_frozen: bool = field(default=False, init=False, repr=False, compare=False)
    _pysymex_descriptor_assignments: (
        Mapping[str, tuple[object, tuple[object, ...] | None]] | None
    ) = field(default=None, init=False, repr=False, compare=False)
    _pysymex_static_class_attrs: Mapping[str, object] | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )
    _pysymex_trusted_cached_property: bool = field(
        default=False,
        init=False,
        repr=False,
        compare=False,
    )
    _pysymex_plain_class_definition: bool = field(
        default=False,
        init=False,
        repr=False,
        compare=False,
    )
    _pysymex_contract_decorator_names: tuple[str, ...] | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )
    _pysymex_metaclass_value: object | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )
    _pysymex_declared_descriptors: Mapping[str, object] | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )
    _pysymex_init_type_hints: Mapping[str, object] | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )
    _pysymex_generic_alias_origin: object | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )
    _pysymex_generic_alias_args: tuple[object, ...] = field(
        default_factory=tuple,
        init=False,
        repr=False,
        compare=False,
    )
    pattern: str | None = field(default=None, init=False, repr=False, compare=False)
    annotations: Mapping[str, object] | SymbolicDict | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )
    _hash_cache: int | None = field(default=None, init=False, repr=False, compare=False)
    digest_size: int | None = field(default=None, init=False, repr=False, compare=False)
    hex: str | None = field(default=None, init=False, repr=False, compare=False)

    def attach_modeled_object(self, value: object) -> None:
        """Attach an execution-side modeled payload to this carrier."""
        self._modeled_object = value

    def attach_modeled_constant(self, value: object) -> None:
        """Attach a concrete value as both modeled payload and constant payload."""
        self._modeled_object = value
        self._constant_value = value

    def attach_constant_value(self, value: object) -> None:
        """Attach a concrete constant payload."""
        self._constant_value = value

    def rename(self, name: str) -> None:
        """Replace the diagnostic name for this value."""
        self._name = name

    def mark_receiver_active(self) -> None:
        """Mark this value as receiver-like metadata."""
        self._h_active = True

    def set_generic_alias_metadata(self, origin: object, args: tuple[object, ...]) -> None:
        """Attach runtime generic-alias metadata."""
        self._pysymex_generic_alias_origin = origin
        self._pysymex_generic_alias_args = args

    def set_runtime_type(self, type_name: str) -> None:
        """Set the runtime type label returned before affinity/type predicates."""
        self._type = type_name

    def clear_hash_cache(self) -> None:
        """Discard a cached concrete hash after retained payload mutation."""
        self._hash_cache = None

    def __copy__(self) -> SymbolicValue:
        """Return a shallow carrier copy over immutable/cached payload channels."""
        self_type = type(self)
        clone = (
            SymbolicValue.__new__(SymbolicValue)
            if self_type is SymbolicValue
            else self_type.__new__(self_type)
        )
        clone.z3_int = self.z3_int
        clone.is_int = self.is_int
        clone.z3_bool = self.z3_bool
        clone.is_bool = self.is_bool
        clone.z3_float = self.z3_float
        clone.is_float = self.is_float
        clone.z3_str = self.z3_str
        clone.is_str = self.is_str
        clone.z3_bytes = self.z3_bytes
        clone.is_bytes = self.is_bytes
        clone.z3_addr = self.z3_addr
        clone.is_obj = self.is_obj
        clone.z3_array = self.z3_array
        clone.is_list = self.is_list
        clone.is_dict = self.is_dict
        clone.is_tuple = self.is_tuple
        clone.is_set = self.is_set
        clone._name = self._name
        clone.is_path = self.is_path
        clone.is_none = self.is_none
        clone._constant_value = self._constant_value
        clone._bv_cache = self._bv_cache
        clone.affinity_type = self.affinity_type
        clone._h_active = self._h_active
        clone.min_val = self.min_val
        clone.max_val = self.max_val
        clone._truthy_cache = self._truthy_cache
        clone._falsy_cache = self._falsy_cache
        clone.model_name = self.model_name
        clone._modeled_object = self._modeled_object
        clone._type = self._type
        clone._pysymex_bases_complete = self._pysymex_bases_complete
        clone._pysymex_base_values = self._pysymex_base_values
        clone._pysymex_literal_enum_members = self._pysymex_literal_enum_members
        clone._pysymex_named_tuple_fields = self._pysymex_named_tuple_fields
        clone._pysymex_dataclass_fields = self._pysymex_dataclass_fields
        clone._pysymex_dataclass_frozen = self._pysymex_dataclass_frozen
        clone._pysymex_descriptor_assignments = self._pysymex_descriptor_assignments
        clone._pysymex_static_class_attrs = self._pysymex_static_class_attrs
        clone._pysymex_trusted_cached_property = self._pysymex_trusted_cached_property
        clone._pysymex_plain_class_definition = self._pysymex_plain_class_definition
        clone._pysymex_contract_decorator_names = self._pysymex_contract_decorator_names
        clone._pysymex_metaclass_value = self._pysymex_metaclass_value
        clone._pysymex_declared_descriptors = self._pysymex_declared_descriptors
        clone._pysymex_init_type_hints = self._pysymex_init_type_hints
        clone._pysymex_generic_alias_origin = self._pysymex_generic_alias_origin
        clone._pysymex_generic_alias_args = self._pysymex_generic_alias_args
        clone.pattern = self.pattern
        clone.annotations = self.annotations
        clone._hash_cache = self._hash_cache
        clone.digest_size = self.digest_size
        clone.hex = self.hex
        return clone

    def replace_retained_set(self, values: set[object]) -> None:
        """Replace exact retained set payload and synchronized hash metadata."""
        retained_values = set(values)
        self._constant_value = retained_values
        self._modeled_object = retained_values
        self._hash_cache = None

    def set_annotations(self, annotations: Mapping[str, object] | SymbolicDict) -> None:
        """Attach annotation metadata to this value carrier."""
        self.annotations = annotations

    def set_class_bases(self, bases_complete: bool, base_values: tuple[object, ...]) -> None:
        """Attach static class-base metadata."""
        self._pysymex_bases_complete = bases_complete
        self._pysymex_base_values = base_values

    def set_literal_enum_members(self, members: Mapping[str, object]) -> None:
        """Attach statically resolved enum members."""
        self._pysymex_literal_enum_members = members

    def set_named_tuple_fields(self, fields: tuple[str, ...]) -> None:
        """Attach statically resolved named-tuple fields."""
        self._pysymex_named_tuple_fields = fields

    def set_dataclass_metadata(
        self,
        fields: tuple[tuple[str, str | None, bool, object, str | None], ...],
        frozen: bool,
    ) -> None:
        """Attach statically resolved dataclass metadata."""
        self._pysymex_dataclass_fields = fields
        self._pysymex_dataclass_frozen = frozen

    def set_descriptor_assignments(
        self,
        assignments: Mapping[str, tuple[object, tuple[object, ...] | None]],
    ) -> None:
        """Attach statically resolved descriptor assignments."""
        self._pysymex_descriptor_assignments = assignments

    def set_static_class_attrs(self, attributes: Mapping[str, object]) -> None:
        """Attach statically resolved class attributes."""
        self._pysymex_static_class_attrs = attributes

    def set_contract_decorator_names(self, names: frozenset[str]) -> None:
        """Attach statically resolved PySyMex contract decorator names."""
        self._pysymex_contract_decorator_names = tuple(sorted(names))

    def set_metaclass_value(self, value: object) -> None:
        """Attach statically resolved metaclass metadata."""
        self._pysymex_metaclass_value = value

    def set_init_type_hints(self, hints: Mapping[str, object]) -> None:
        """Attach statically resolved constructor type-hint metadata."""
        self._pysymex_init_type_hints = hints

    def mark_trusted_cached_property(self) -> None:
        """Mark class metadata as allowing trusted cached-property modeling."""
        self._pysymex_trusted_cached_property = True

    def mark_plain_class_definition(self) -> None:
        """Mark the value as a plain class definition."""
        self._pysymex_plain_class_definition = True

    @property
    def name(self) -> str:
        """Return the name of the symbolic value."""
        return self._name

    @property
    def runtime_type(self) -> str | None:
        """Return the explicit runtime type label, when one has been set."""
        return self._type

    @property
    def init_type_hints(self) -> Mapping[str, object] | None:
        """Return statically resolved constructor type-hint metadata."""
        return self._pysymex_init_type_hints

    @property
    def plain_class_definition(self) -> bool:
        """Return whether this carrier represents a plain class definition."""
        return self._pysymex_plain_class_definition

    @property
    def type_tag(self) -> str:
        """Return the CPython-facing type tag of the symbolic value."""
        if self._type:
            return self._type
        affinity_type = self.affinity_type
        if affinity_type != "unknown":
            if affinity_type == "none":
                return "NoneType"
            if affinity_type == "obj":
                return "object"
            return affinity_type
        channel_order = (
            (self.is_none, AffinityKind.NONE),
            (self.is_bool, AffinityKind.BOOL),
            (self.is_int, AffinityKind.INT),
            (self.is_float, AffinityKind.FLOAT),
            (self.is_str, AffinityKind.STR),
            (self.is_bytes, AffinityKind.BYTES),
            (self.is_list, AffinityKind.LIST),
            (self.is_dict, AffinityKind.DICT),
            (self.is_tuple, AffinityKind.TUPLE),
            (self.is_set, AffinityKind.SET),
            (self.is_obj, AffinityKind.OBJECT),
            (self.is_path, AffinityKind.PATH),
        )
        for flag, affinity in channel_order:
            if z3.is_true(flag):
                return python_type_name_for_affinity(affinity)
        return python_type_name_for_affinity(AffinityKind.OBJECT)

    def to_z3(self) -> z3.ExprRef:
        """Return the integer payload channel used as the primary expression."""
        return self.z3_int

    def symbolic_length(self) -> z3.ArithRef | None:
        """Return the active sequence/container length channel, when modeled."""
        if self.affinity_type == AffinityKind.STR:
            return z3.Length(self.z3_str)
        if self.affinity_type == AffinityKind.BYTES:
            return z3.Length(self.z3_bytes)
        if self.affinity_type in LENGTH_CHANNEL_AFFINITIES:
            return self.z3_int
        if z3.is_true(self.is_str):
            return z3.Length(self.z3_str)
        if z3.is_true(self.is_bytes):
            return z3.Length(self.z3_bytes)
        if any(
            z3.is_true(type_flag)
            for type_flag in (self.is_list, self.is_dict, self.is_tuple, self.is_set)
        ):
            return self.z3_int
        return None

    @property
    def as_bv(self) -> z3.BitVecRef:
        """Return cached 64-bit view of this carrier's integer payload channel."""
        if self._bv_cache is None:
            self._bv_cache = ScalarValueOps.int_to_bv(self.z3_int)
        return self._bv_cache

    def hash_value(self) -> int:
        """Return a structural hash over represented Z3 payload/type channels."""
        if self._hash_cache is not None:
            return self._hash_cache
        h = self.z3_int.hash()
        h = (h * 31) ^ self.is_int.hash()
        h = (h * 31) ^ self.z3_bool.hash()
        h = (h * 31) ^ self.is_bool.hash()
        h = (h * 31) ^ self.is_none.hash()
        h = (h * 31) ^ self.z3_str.hash()
        h = (h * 31) ^ self.is_str.hash()
        h = (h * 31) ^ self.z3_bytes.hash()
        h = (h * 31) ^ self.is_bytes.hash()
        h = (h * 31) ^ self.z3_addr.hash()
        h = (h * 31) ^ self.is_obj.hash()
        h = (h * 31) ^ self.is_path.hash()
        h = (h * 31) ^ self.is_list.hash()
        h = (h * 31) ^ self.is_dict.hash()
        h = (h * 31) ^ self.is_tuple.hash()
        h = (h * 31) ^ self.is_set.hash()
        h = (h * 31) ^ self.z3_float.hash()
        h = (h * 31) ^ self.is_float.hash()
        if self.z3_array is not None:
            h = (h * 31) ^ self.z3_array.hash()
        self._hash_cache = h
        return h

    def __hash__(self) -> int:
        """Return the carrier's structural hash for Python hash containers.

        CPython sets __hash__ = None for dataclasses that define __eq__ without
        __hash__, which makes instances unhashable and causes `if sv == other:`
        comparisons to always be truthy (non-None object is truthy). By
        explicitly delegating to hash_value() we restore both invariants.
        (Fixes BUG-003.)
        """
        return self.hash_value()

    def __repr__(self) -> str:
        """Return the diagnostic representation for this scalar carrier."""
        t = self.type_tag
        return f"SymbolicValue(name={self._name}, type={t})"


bind_state_symbolic_value_class(SymbolicValue)
bind_symbolic_value_arithmetic_classes(SymbolicValue)
bind_symbolic_value_bitwise_classes(SymbolicValue)
bind_comparison_symbolic_value_class(SymbolicValue)
bind_symbolic_value_factory_classes(SymbolicValue, object)
