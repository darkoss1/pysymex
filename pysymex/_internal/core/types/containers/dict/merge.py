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

"""Persistent update and conditional-merge operations for symbolic dictionaries."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.constants import Z3_TRUE
from pysymex._internal.core.types.base import fresh_name
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.core.z3.expression_ops import Z3ExpressionOps

if TYPE_CHECKING:
    from pysymex._internal.core.types.containers.dicts import SymbolicDict


class SymbolicDictMergeMixin:
    """Build new symbolic dictionaries from updates or path conditions.

    Limitations:
        Symbolic updates approximate result length with bounds, and conditional
        merges do not retain concrete-item metadata.
    """

    def update(
        self,
        other: SymbolicDict | Mapping[object, object] | Mapping[str, object],
    ) -> tuple[SymbolicDict, z3.BoolRef]:
        """Return an updated dictionary and any required length constraint.

        Notes:
            Concrete updates return a tautological constraint. For a symbolic
            source without retained concrete items, the new length is bounded
            between the larger input length and their sum; overlapping keys
            are not counted exactly.

        """
        this = cast("SymbolicDict", self)
        if isinstance(other, Mapping):
            res = this
            all_constraints: list[z3.BoolRef] = []
            for k, v in other.items():
                res = res.__setitem__(k, v)
            return res, z3.And(*all_constraints) if all_constraints else Z3_TRUE
        other_concrete = getattr(other, "_concrete_items", None)
        if other_concrete is not None:
            res = this
            for k, v in other_concrete.items():
                res = res.__setitem__(k, v)
            return res, Z3_TRUE
        k = z3.String(fresh_name("k"))

        other_has_k = z3.Select(other.known_keys, k)
        new_array = cast(
            "z3.ArrayRef",
            z3.Lambda(
                [k],
                z3.If(
                    other_has_k,
                    z3.Select(other.z3_array, k),
                    z3.Select(this.z3_array, k),
                ),
            ),
        )

        # New keys is union of self and other keys
        new_keys = cast(
            "z3.ArrayRef",
            z3.Lambda(
                [k],
                z3.Or(z3.Select(this.known_keys, k), z3.Select(other.known_keys, k)),
            ),
        )

        new_len = z3.Int(fresh_name("updated_len"))

        max_len = z3.If(this.z3_len > other.z3_len, this.z3_len, other.z3_len)
        sum_len = this.z3_len + other.z3_len

        constraint = z3.And(new_len >= max_len, new_len <= sum_len)

        return type(this)(
            _name=f"{this.name}.update({other.name})",
            z3_array=new_array,
            known_keys=new_keys,
            z3_len=new_len,
        ), constraint

    def conditional_merge(
        self,
        other: object,
        condition: z3.BoolRef,
    ) -> SymbolicDict | SymbolicValue:
        """Return a conditional value or dictionary over both branch values.

        Notes:
            Matching Z3 fields are retained directly. A dictionary result
            carries conditional arrays/length but not concrete-item metadata.

        """
        this = cast("SymbolicDict", self)
        if not isinstance(other, type(this)):
            val_self = SymbolicValue.from_specialized(this)
            return val_self.conditional_merge(other, condition)

        if this is other:
            return this

        are_arrays_equal = this.z3_array is other.z3_array or Z3ExpressionOps.safe_eq(
            this.z3_array,
            other.z3_array,
        )
        new_array = (
            this.z3_array if are_arrays_equal else z3.If(condition, this.z3_array, other.z3_array)
        )

        are_keys_equal = this.known_keys is other.known_keys or Z3ExpressionOps.safe_eq(
            this.known_keys,
            other.known_keys,
        )
        new_keys = (
            this.known_keys
            if are_keys_equal
            else z3.If(condition, this.known_keys, other.known_keys)
        )

        are_lens_equal = this.z3_len is other.z3_len or Z3ExpressionOps.safe_eq(
            this.z3_len,
            other.z3_len,
        )
        new_len = this.z3_len if are_lens_equal else z3.If(condition, this.z3_len, other.z3_len)

        return type(this)(
            _name=f"If({condition}, {this.name}, {other.name})",
            z3_array=new_array,
            known_keys=new_keys,
            z3_len=new_len,
        )
