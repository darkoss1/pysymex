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

"""Concrete value conversion for scalar symbolic values."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pysymex._internal.core.types.scalars.value.scalar_ops as helpers
from pysymex._internal.core.constants import (
    Z3_FALSE,
    Z3_FLOAT_ZERO,
    Z3_ONE,
    Z3_TRUE,
    Z3_ZERO,
)
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.affinity import AffinityKind
from pysymex._internal.core.types.scalars.value.protocols import (
    ValueConstructor,
    unbound_symbolic_value_constructor,
)
from pysymex._internal.guards import RuntimeObjectGuards

if TYPE_CHECKING:
    from pysymex._internal.core.types.scalars.values import SymbolicValue

_symbolic_value_cls = unbound_symbolic_value_constructor()
_symbolic_string_cls: type[object] = object
FROM_CONST_CACHE = cast(
    "dict[str | tuple[str, int] | tuple[str, float], SymbolicValue]",
    helpers.FROM_CONST_CACHE,
)
FROM_CONST_CACHE_LIMIT = helpers.FROM_CONST_CACHE_LIMIT
FROM_CONST_CACHE_LOCK = helpers.FROM_CONST_CACHE_LOCK


def _copy_cached_constant(value: SymbolicValue) -> SymbolicValue:
    """Return an execution-isolated carrier over cached immutable Z3 channels."""
    return value.__copy__()


def _store_constant_template(
    key: str | tuple[str, int] | tuple[str, float],
    value: SymbolicValue,
) -> None:
    """Store an unexposed carrier template while the bounded cache has room."""
    with FROM_CONST_CACHE_LOCK:
        if len(FROM_CONST_CACHE) < FROM_CONST_CACHE_LIMIT:
            FROM_CONST_CACHE[key] = _copy_cached_constant(value)


def bind_constant_symbolic_value_classes(
    value_cls: ValueConstructor,
    string_cls: type[object],
) -> None:
    """Bind carrier classes used by concrete-value conversion."""
    global _symbolic_value_cls, _symbolic_string_cls
    _symbolic_value_cls = value_cls
    _symbolic_string_cls = string_cls


def _cached_constant(key: str | tuple[str, int] | tuple[str, float]) -> SymbolicValue | None:
    """Return an isolated cached constant when the cache contains a valid carrier."""
    cached = FROM_CONST_CACHE.get(key)
    return _copy_cached_constant(cached) if cached is not None else None


def _from_symbolic_float(value: object) -> SymbolicValue | None:
    """Convert the dedicated symbolic-float carrier before generic type-tag handling."""
    from pysymex._internal.core.types.numeric.float import SymbolicFloat

    if not isinstance(value, SymbolicFloat):
        return None
    return _symbolic_value_cls(
        _name=value.name,
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        z3_float=value.z3_expr,
        is_float=Z3_TRUE,
        is_path=Z3_FALSE,
        affinity_type=AffinityKind.FLOAT,
    )


def _from_none_constant() -> SymbolicValue:
    """Return the unified carrier for concrete ``None``."""
    cached = _cached_constant("None")
    if cached is not None:
        return cached
    value = _symbolic_value_cls(
        _name="None",
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_path=Z3_FALSE,
        is_none=Z3_TRUE,
        affinity_type=AffinityKind.NONE,
        _h_active=False,
    )
    _store_constant_template("None", value)
    return value


def _from_bool_constant(value: bool) -> SymbolicValue:
    """Return the unified carrier for a concrete boolean."""
    key = "True" if value else "False"
    cached = _cached_constant(key)
    if cached is not None:
        return cached
    if value:
        result = _symbolic_value_cls(
            _name="True",
            z3_int=Z3_ONE,
            is_int=Z3_FALSE,
            z3_bool=Z3_TRUE,
            is_bool=Z3_TRUE,
            is_path=Z3_FALSE,
            _constant_value=True,
            affinity_type=AffinityKind.BOOL,
            min_val=1,
            max_val=1,
        )
    else:
        result = _symbolic_value_cls(
            _name="False",
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_TRUE,
            is_path=Z3_FALSE,
            _constant_value=False,
            affinity_type=AffinityKind.BOOL,
            min_val=0,
            max_val=0,
        )
    _store_constant_template(key, result)
    return result


def _from_int_constant(value: int) -> SymbolicValue:
    """Return the unified carrier for a concrete integer."""
    key = ("int", value)
    cached = _cached_constant(key)
    if cached is not None:
        return cached
    result = _symbolic_value_cls(
        _name=str(value),
        z3_int=ConstraintValues.int(value),
        is_int=Z3_TRUE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        z3_float=Z3_FLOAT_ZERO,
        is_float=Z3_FALSE,
        is_path=Z3_FALSE,
        _constant_value=value,
        affinity_type=AffinityKind.INT,
        min_val=value,
        max_val=value,
    )
    _store_constant_template(key, result)
    return result


def _float_int_channel(value: float):
    """Return the integer projection channel for a concrete float."""
    try:
        return ConstraintValues.int(int(value))
    except (ValueError, OverflowError):
        return Z3_ZERO


def _from_float_constant(value: float) -> SymbolicValue:
    """Return the unified carrier for a concrete float."""
    key = ("float", value)
    cached = _cached_constant(key)
    if cached is not None:
        return cached
    result = _symbolic_value_cls(
        _name=str(value),
        z3_int=_float_int_channel(value),
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        z3_float=ConstraintValues.float64(value),
        is_float=Z3_TRUE,
        is_path=Z3_FALSE,
        _constant_value=value,
        affinity_type=AffinityKind.FLOAT,
        min_val=value,
        max_val=value,
    )
    _store_constant_template(key, result)
    return result


def _from_primitive_constant(value: object) -> SymbolicValue | None:
    """Convert cacheable Python primitives while preserving bool-before-int order."""
    if value is None:
        return _from_none_constant()
    value_type = type(value)
    if value_type is bool:
        return _from_bool_constant(cast("bool", value))
    if value_type is int:
        return _from_int_constant(cast("int", value))
    if value_type is float:
        return _from_float_constant(cast("float", value))
    if isinstance(value, bool):
        return _from_bool_constant(value)
    if isinstance(value, int):
        return _from_int_constant(value)
    if isinstance(value, float):
        return _from_float_constant(value)
    return None


def _new_modeled_constant(value: object) -> SymbolicValue:
    """Create the baseline carrier for non-primitive concrete Python values."""
    return _symbolic_value_cls(
        _name=str(value),
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_path=Z3_FALSE,
        _constant_value=value,
    )


def _mark_modeled_sequence(value: object, result: SymbolicValue) -> bool:
    """Mark list/tuple/set-like constants on a baseline modeled carrier."""
    if RuntimeObjectGuards.list(value):
        result.is_list = Z3_TRUE
        result.affinity_type = AffinityKind.LIST
    elif RuntimeObjectGuards.tuple(value):
        result.is_tuple = Z3_TRUE
        result.affinity_type = AffinityKind.TUPLE
    elif RuntimeObjectGuards.set(value) or RuntimeObjectGuards.frozenset(value):
        result.is_set = Z3_TRUE
        result.affinity_type = (
            AffinityKind.SET if isinstance(value, set) else AffinityKind.FROZENSET
        )
    else:
        return False
    result.z3_int = ConstraintValues.int(len(value))
    result.attach_modeled_constant(value)
    return True


def _mark_modeled_mapping_or_bytes(value: object, result: SymbolicValue) -> bool:
    """Mark dict/bytes constants on a baseline modeled carrier."""
    if RuntimeObjectGuards.dict(value):
        result.is_dict = Z3_TRUE
        result.affinity_type = AffinityKind.DICT
        result.z3_int = ConstraintValues.int(len(value))
    elif isinstance(value, bytes):
        from pysymex._internal.core.types.containers.bytes import SymbolicBytes

        symbolic_bytes = SymbolicBytes.concrete(value)
        result.is_bytes = Z3_TRUE
        result.affinity_type = AffinityKind.BYTES
        result.z3_bytes = symbolic_bytes.z3_bytes
        result.z3_int = symbolic_bytes.z3_len
    else:
        return False
    result.attach_modeled_constant(value)
    return True


def _from_modeled_constant(value: object) -> SymbolicValue:
    """Convert non-primitive concrete Python values into modeled carriers."""
    result = _new_modeled_constant(value)
    if not _mark_modeled_sequence(value, result) and not _mark_modeled_mapping_or_bytes(
        value,
        result,
    ):
        result.attach_modeled_object(value)
    return result


class ValueConstantMixin:
    """Create unified scalar carriers from concrete Python objects."""

    @staticmethod
    def from_const(value: object) -> SymbolicValue:
        """Create a carrier for a concrete Python value.

        Notes:
            ``None``, booleans, integers, and floats may reuse bounded cache
            entries. Lists and dictionaries retain their concrete modeled
            objects and expose lengths through the integer channel.

        Limitations:
            Other arbitrary objects are retained as modeled payloads without
            introducing object-type predicates or symbolic behavior here.

        """
        value_type = type(value)
        if value_type is int:
            int_value: int = value  # pyright: ignore[reportAssignmentType]
            cached = FROM_CONST_CACHE.get(("int", int_value))
            return cached.__copy__() if cached is not None else _from_int_constant(int_value)
        if value_type is bool:
            bool_value: bool = value  # pyright: ignore[reportAssignmentType]
            key = "True" if bool_value else "False"
            cached = FROM_CONST_CACHE.get(key)
            return cached.__copy__() if cached is not None else _from_bool_constant(bool_value)
        if value is None:
            cached = FROM_CONST_CACHE.get("None")
            return cached.__copy__() if cached is not None else _from_none_constant()
        if value_type is float:
            float_value: float = value  # pyright: ignore[reportAssignmentType]
            cached = FROM_CONST_CACHE.get(("float", float_value))
            return cached.__copy__() if cached is not None else _from_float_constant(float_value)
        primitive = _from_primitive_constant(value)
        if primitive is not None:
            return primitive
        if value_type is str:
            from pysymex._internal.core.types.scalars.strings import SymbolicString

            str_value: str = value  # pyright: ignore[reportAssignmentType]
            return _symbolic_value_cls.from_specialized(
                SymbolicString.from_const(str_value),
            )
        from pysymex._internal.core.types.scalars.values import SymbolicValue as _SV

        if isinstance(value, _SV):
            return value
        symbolic_float = _from_symbolic_float(value)
        if symbolic_float is not None:
            return symbolic_float
        if hasattr(value, "type_tag"):
            return _symbolic_value_cls.from_specialized(value)
        if isinstance(value, str):
            from pysymex._internal.core.types.scalars.strings import SymbolicString

            return _symbolic_value_cls.from_specialized(SymbolicString.from_const(value))
        return _from_modeled_constant(value)
