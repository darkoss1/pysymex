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

"""Unconstrained symbolic values for unsupported or unmodeled results.

``HavocValue.havoc`` creates fresh symbolic components plus an exactly-one
type constraint. Calls, attribute access, and subscripts on a havoc value
create additional havoc values.

Limitations:
    Havoc explicitly records precision loss. A havoc-dependent expression is
    not by itself proof of a concrete runtime result or a definite issue.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypeGuard

import z3

from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.core.types.scalars.values import exactly_one_bool

_havoc_values_created = False


def _new_havoc_attributes() -> dict[str, tuple[HavocValue, z3.BoolRef]]:
    """Create an empty per-value attribute result cache."""
    return {}


@dataclass(slots=True)
class HavocValue(SymbolicValue):
    """Symbolic value marked as lacking concrete modeled provenance.

    The value carries fresh Z3 fields, an explicit marker, and an exposed
    attribute-map field. Create values through :meth:`havoc` so the required
    type constraint is returned alongside the value.

    Limitations:
        Attribute access, calls, and subscripts construct fresh havoc results;
        this class does not itself add their returned constraints to a path.
    """

    _is_havoc: bool = field(default=True, init=False, repr=False, compare=False)
    _attributes: dict[str, tuple[HavocValue, z3.BoolRef]] = field(
        default_factory=_new_havoc_attributes, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        """Register havoc allocation and preserve scalar carrier initialization."""
        global _havoc_values_created

        _havoc_values_created = True
        SymbolicValue.__post_init__(self)

    @staticmethod
    def havoc(
        name: str,
    ) -> tuple[HavocValue, z3.BoolRef]:
        """Create a fresh havoc value with its own Z3 variables.

        Args:
            name: Prefix used for generated Z3 variable names.

        Returns:
            A havoc value and its exactly-one symbolic type constraint.
        """
        z3_int = z3.Int(f"{name}_int")
        z3_bool = z3.Bool(f"{name}_bool")
        z3_float = z3.FP(f"{name}_float", z3.Float64())
        z3_str = z3.String(f"{name}_str")
        z3_addr = z3.Int(f"{name}_addr")

        is_int = z3.Bool(f"{name}_is_int")
        is_bool = z3.Bool(f"{name}_is_bool")
        is_str = z3.Bool(f"{name}_is_str")
        is_path = z3.Bool(f"{name}_is_path")
        is_obj = z3.Bool(f"{name}_is_obj")
        is_none = z3.Bool(f"{name}_is_none")
        is_float = z3.Bool(f"{name}_is_float")

        is_list = z3.Bool(f"{name}_is_list")
        is_dict = z3.Bool(f"{name}_is_dict")

        type_vars = [is_int, is_bool, is_str, is_path, is_obj, is_none, is_float, is_list, is_dict]
        type_constraint = exactly_one_bool(type_vars)

        val = HavocValue(
            z3_int=z3_int,
            is_int=is_int,
            z3_bool=z3_bool,
            is_bool=is_bool,
            z3_float=z3_float,
            is_float=is_float,
            z3_str=z3_str,
            is_str=is_str,
            z3_addr=z3_addr,
            is_obj=is_obj,
            is_path=is_path,
            is_none=is_none,
            is_list=is_list,
            is_dict=is_dict,
            _name=name,
        )
        return val, type_constraint

    def __getitem__(self, key: object) -> tuple[HavocValue, z3.BoolRef]:
        """Return fresh havoc for a subscript and its type constraint."""
        name = f"{self._name}[{getattr(key, 'name', str(key))}]"
        return HavocValue.havoc(name)

    def __getattr__(self, name: str) -> tuple[HavocValue, z3.BoolRef]:
        """Return fresh havoc for a public attribute and its type constraint.

        Raises:
            AttributeError: If ``name`` starts with an underscore.
        """
        if name.startswith("_"):
            raise AttributeError(name)
        full_name = f"{self._name}.{name}"
        return HavocValue.havoc(full_name)

    def __call__(self, *args: object, **kwargs: object) -> tuple[HavocValue, z3.BoolRef]:
        """Return fresh havoc for a call result and its type constraint."""
        full_name = f"{self._name}()"
        return HavocValue.havoc(full_name)

    def __repr__(self) -> str:
        """Return the diagnostic representation for this havoc carrier."""
        return f"HavocValue({self._name})"

    def get_cached_attributes(self) -> dict[str, tuple[HavocValue, z3.BoolRef]]:
        """Return the attribute mapping stored on this havoc value.

        Notes:
            This module does not populate the mapping during ``__getattr__``.
        """
        return self._attributes


def is_havoc(value: object) -> TypeGuard[HavocValue]:
    """Return ``True`` if *value* is a :class:`HavocValue`."""
    return type(value) is HavocValue


def havoc_values_may_exist() -> bool:
    """Return whether any :class:`HavocValue` has been constructed in this process."""
    return _havoc_values_created


def has_havoc(*values: object) -> bool:
    """Return ``True`` if **any** of *values* is a :class:`HavocValue`."""
    if not _havoc_values_created:
        return False
    return any(type(value) is HavocValue for value in values)
