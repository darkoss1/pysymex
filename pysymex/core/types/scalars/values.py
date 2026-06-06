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

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import z3

from pysymex.core.cache.control import register_process_cache_clearer
from pysymex.core.constants import (
    Z3_EMPTY_STRING,
    Z3_FALSE,
    Z3_FLOAT_ZERO,
    Z3_ZERO,
)
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.base import SymbolicType
from pysymex.core.types.scalars.value.additive import (
    SymbolicValueAdditiveMixin,
    bind_symbolic_value_class as _bind_additive_symbolic_value_class,
)
from pysymex.core.types.scalars.value.bitwise.logic import (
    SymbolicValueBitwiseLogicMixin,
    bind_symbolic_value_class as _bind_bitwise_logic_symbolic_value_class,
)
from pysymex.core.types.scalars.value.bitwise.xor import (
    SymbolicValueBitwiseXorMixin,
    bind_symbolic_value_class as _bind_bitwise_xor_symbolic_value_class,
)
from pysymex.core.types.scalars.value.comparisons import (
    SymbolicValueComparisonMixin,
    bind_symbolic_value_class as _bind_comparison_symbolic_value_class,
)
from pysymex.core.types.scalars.value.constants import (
    SymbolicValueConstantMixin,
    bind_symbolic_value_classes as _bind_constant_symbolic_value_classes,
)
from pysymex.core.types.scalars.value.creators import (
    SymbolicValueCreatorMixin,
    bind_symbolic_value_classes as _bind_creator_symbolic_value_classes,
)
from pysymex.core.types.scalars.value.division import (
    SymbolicValueDivisionMixin,
    bind_symbolic_value_class as _bind_division_symbolic_value_class,
)
from pysymex.core.types.scalars.value import helpers as _scalar_value_helpers
from pysymex.core.types.scalars.value.helpers import (
    BV_WIDTH as BV_WIDTH,
    FROM_CONST_CACHE as FROM_CONST_CACHE,
    FROM_CONST_CACHE_LIMIT as FROM_CONST_CACHE_LIMIT,
    STRING_CONST_CACHE as STRING_CONST_CACHE,
    STRING_CONST_CACHE_LIMIT as STRING_CONST_CACHE_LIMIT,
    STRING_CONST_CACHE_LOCK as STRING_CONST_CACHE_LOCK,
    SYMBOLIC_CACHE as SYMBOLIC_CACHE,
    SYMBOLIC_CACHE_LIMIT as SYMBOLIC_CACHE_LIMIT,
    bind_scalar_value_classes as _bind_helper_scalar_value_classes,
    bv_to_int as bv_to_int,
    exactly_one_bool as exactly_one_bool,
    fresh_name as fresh_name,
    int_to_bv as int_to_bv,
    int_to_bv as _int_to_bv,
    is_concrete_val as is_concrete_val,
    py_floor_div as py_floor_div,
    py_mod as py_mod,
)
from pysymex.core.types.scalars.value.protocols import SymbolicValueConstructor
from pysymex.core.types.scalars.value.power import (
    SymbolicValuePowerMixin,
    bind_symbolic_value_class as _bind_power_symbolic_value_class,
)
from pysymex.core.types.scalars.value.remainder import (
    SymbolicValueRemainderMixin,
    bind_symbolic_value_class as _bind_remainder_symbolic_value_class,
)
from pysymex.core.types.scalars.value.shifts import (
    SymbolicValueShiftMixin,
    bind_symbolic_value_class as _bind_shift_symbolic_value_class,
)
from pysymex.core.types.scalars.value.specialization import (
    SymbolicValueSpecializationMixin,
    bind_symbolic_value_classes as _bind_specialization_symbolic_value_classes,
)
from pysymex.core.types.scalars.value.state import (
    SymbolicValueStateMixin,
    bind_symbolic_value_class as _bind_state_symbolic_value_class,
)

if TYPE_CHECKING:
    from typing import TypeAlias

    from pysymex.core.types.containers.bytes import SymbolicBytes
    from pysymex.core.types.containers.dict_views import SymbolicDictView
    from pysymex.core.types.containers.dicts import SymbolicDict
    from pysymex.core.types.containers.lists import SymbolicList
    from pysymex.core.types.containers.objects import SymbolicObject

    AnySymbolic: TypeAlias = "SymbolicValue | SymbolicNone | SymbolicString | SymbolicBytes | SymbolicList | SymbolicDict | SymbolicDictView | SymbolicObject"
else:
    AnySymbolic = object

_FROM_CONST_CACHE_LOCK = _scalar_value_helpers.FROM_CONST_CACHE_LOCK
_Z3_OP_BV2INT = _scalar_value_helpers.Z3_OP_BV2INT
_Z3_OP_BXOR = _scalar_value_helpers.Z3_OP_BXOR
_apply_concrete_integral_binary_op = _scalar_value_helpers.apply_concrete_integral_binary_op
_apply_concrete_integral_unary_op = _scalar_value_helpers.apply_concrete_integral_unary_op
_apply_concrete_numeric_binary_op = _scalar_value_helpers.apply_concrete_numeric_binary_op
_bv_to_int = _scalar_value_helpers.bv_to_int
_cached_int_value_is_usable = _scalar_value_helpers.cached_int_value_is_usable
_extract_concrete_integral = _scalar_value_helpers.extract_concrete_integral
_extract_concrete_numeric = _scalar_value_helpers.extract_concrete_numeric
_guarded_nonzero_divisor = _scalar_value_helpers.guarded_nonzero_divisor
is_list_of_objects = _scalar_value_helpers.is_list_of_objects
_next_address = _scalar_value_helpers.next_address
_py_floor_div = _scalar_value_helpers.py_floor_div
_py_mod = _scalar_value_helpers.py_mod


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


def _bind_arithmetic_symbolic_value_class(value_cls: SymbolicValueConstructor) -> None:
    """Bind the carrier class into all arithmetic mixin modules."""
    _bind_additive_symbolic_value_class(value_cls)
    _bind_remainder_symbolic_value_class(value_cls)
    _bind_division_symbolic_value_class(value_cls)


def _bind_bitwise_symbolic_value_class(value_cls: SymbolicValueConstructor) -> None:
    """Bind the carrier class into all bitwise mixin modules."""
    _bind_bitwise_logic_symbolic_value_class(value_cls)
    _bind_bitwise_xor_symbolic_value_class(value_cls)
    _bind_shift_symbolic_value_class(value_cls)
    _bind_power_symbolic_value_class(value_cls)


def _bind_factory_symbolic_value_classes(
    value_cls: SymbolicValueConstructor,
    string_cls: type[object],
) -> None:
    """Bind value and string classes into all factory mixin modules."""
    _bind_creator_symbolic_value_classes(value_cls, string_cls)
    _bind_specialization_symbolic_value_classes(value_cls, string_cls)
    _bind_constant_symbolic_value_classes(value_cls, string_cls)


class SymbolicValueArithmeticMixin(
    SymbolicValueDivisionMixin,
    SymbolicValueRemainderMixin,
    SymbolicValueAdditiveMixin,
):
    """Compose arithmetic operation implementations for ``SymbolicValue``."""

    pass


class SymbolicValueBitwiseMixin(
    SymbolicValuePowerMixin,
    SymbolicValueShiftMixin,
    SymbolicValueBitwiseXorMixin,
    SymbolicValueBitwiseLogicMixin,
):
    """Compose bitwise, shift, and power operations for ``SymbolicValue``."""

    pass


class SymbolicValueFactoryMixin(
    SymbolicValueConstantMixin,
    SymbolicValueSpecializationMixin,
    SymbolicValueCreatorMixin,
):
    """Compose construction and specialization helpers for ``SymbolicValue``."""

    pass


@dataclass(slots=True, eq=False)
class SymbolicValue(
    SymbolicValueComparisonMixin,
    SymbolicValueBitwiseMixin,
    SymbolicValueArithmeticMixin,
    SymbolicValueFactoryMixin,
    SymbolicValueStateMixin,
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
    z3_addr: z3.ArithRef = field(default=Z3_ZERO)
    is_obj: z3.BoolRef = field(default=Z3_FALSE)

    z3_array: z3.ArrayRef | None = field(default=None)
    is_list: z3.BoolRef = field(default=Z3_FALSE)
    is_dict: z3.BoolRef = field(default=Z3_FALSE)

    _name: str = ""
    is_path: z3.BoolRef = field(default=Z3_FALSE)
    is_none: z3.BoolRef = field(default=Z3_FALSE)
    _constant_value: object = field(default=None, compare=False, repr=False)
    _bv_cache: z3.BitVecRef | None = field(default=None, init=False, repr=False, compare=False)

    affinity_type: str = field(default="NoneType", compare=False)
    _h_active: bool = field(default=False)

    def __post_init__(self) -> None:
        """Normalize diagnostic names and mark receiver-like values."""
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
    pattern: str | None = field(default=None, init=False, repr=False, compare=False)
    annotations: Mapping[str, object] | SymbolicDict | None = field(
        default=None, init=False, repr=False, compare=False
    )
    _hash_cache: int | None = field(default=None, init=False, repr=False, compare=False)

    def attach_modeled_object(self, value: object) -> None:
        """Attach an execution-side modeled payload to this carrier."""
        self._modeled_object = value

    def set_runtime_type(self, type_name: str) -> None:
        """Set the runtime type label returned before affinity/type predicates."""
        self._type = type_name

    def set_annotations(self, annotations: Mapping[str, object] | SymbolicDict) -> None:
        """Attach annotation metadata to this value carrier."""
        self.annotations = annotations

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
        if z3.is_true(self.is_float):
            return "float"
        if z3.is_true(self.is_int):
            return "int"
        if z3.is_true(self.is_bool):
            return "bool"
        if z3.is_true(self.is_str):
            return "str"
        return "object"

    def to_z3(self) -> z3.ExprRef:
        """Return the integer payload channel used as the primary expression."""
        return self.z3_int

    @property
    def as_bv(self) -> z3.BitVecRef:
        """Return cached 64-bit view of this carrier's integer payload channel."""
        if self._bv_cache is None:
            self._bv_cache = _int_to_bv(self.z3_int)
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
        h = (h * 31) ^ self.z3_addr.hash()
        h = (h * 31) ^ self.is_obj.hash()
        h = (h * 31) ^ self.is_path.hash()
        h = (h * 31) ^ self.is_list.hash()
        h = (h * 31) ^ self.is_dict.hash()
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


from pysymex.core.types.scalars.strings import SymbolicString

_bind_helper_scalar_value_classes(SymbolicValue, SymbolicString)
_bind_state_symbolic_value_class(SymbolicValue)
_bind_factory_symbolic_value_classes(SymbolicValue, SymbolicString)
_bind_arithmetic_symbolic_value_class(SymbolicValue)
_bind_bitwise_symbolic_value_class(SymbolicValue)
_bind_comparison_symbolic_value_class(SymbolicValue)
