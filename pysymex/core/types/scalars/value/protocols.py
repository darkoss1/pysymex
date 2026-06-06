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

"""Typing helpers shared by scalar value mixins."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

import z3

if TYPE_CHECKING:
    from pysymex.core.types.scalars.values import SymbolicValue as _SymbolicValueType
else:
    _SymbolicValueType = object

SymbolicValueSelf = Any


class SymbolicValueConstructor(Protocol):
    """Constructor and factory surface required by scalar operation mixins."""

    def __call__(
        self,
        *,
        z3_int: z3.ArithRef,
        is_int: z3.BoolRef,
        z3_bool: z3.BoolRef,
        is_bool: z3.BoolRef,
        z3_float: z3.FPRef | None = None,
        is_float: z3.BoolRef | None = None,
        z3_str: z3.SeqRef | None = None,
        is_str: z3.BoolRef | None = None,
        z3_addr: z3.ArithRef | None = None,
        is_obj: z3.BoolRef | None = None,
        z3_array: z3.ArrayRef | None = None,
        is_list: z3.BoolRef | None = None,
        is_dict: z3.BoolRef | None = None,
        _name: str = "",
        is_path: z3.BoolRef | None = None,
        is_none: z3.BoolRef | None = None,
        _constant_value: object = None,
        affinity_type: str = "NoneType",
        _h_active: bool = False,
        min_val: int | float | None = None,
        max_val: int | float | None = None,
    ) -> _SymbolicValueType:
        """Construct a unified carrier from explicit payload and type channels."""
        ...

    def from_const(self, value: object) -> _SymbolicValueType:
        """Construct a carrier for a concrete Python value."""
        ...

    def from_specialized(self, value: object) -> _SymbolicValueType:
        """Convert a specialized symbolic value into unified channels."""
        ...

    def symbolic(self, name: str) -> tuple[_SymbolicValueType, z3.BoolRef]:
        """Create a general carrier and its required type constraint."""
        ...

    def symbolic_int(self, name: str) -> tuple[_SymbolicValueType, z3.BoolRef]:
        """Create an integer-affinity carrier and companion constraint."""
        ...

    def symbolic_float(self, name: str) -> tuple[_SymbolicValueType, z3.BoolRef]:
        """Create a floating-point-affinity carrier and companion constraint."""
        ...

    def symbolic_bool(self, name: str) -> tuple[_SymbolicValueType, z3.BoolRef]:
        """Create a Boolean-affinity carrier and companion constraint."""
        ...
