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

"""Persistent rotation, extension, and conditional merge for symbolic lists."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.base import fresh_name
from pysymex._internal.core.types.scalars.value.scalar_ops import ScalarValueOps
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.core.z3.expression_ops import Z3ExpressionOps

if TYPE_CHECKING:
    from pysymex._internal.core.types.containers.lists import SymbolicList


class ListSequenceOpsMixin:
    """Construct transformed list values without mutating their source list.

    Limitations:
        Conditional merge and symbolic extension return array/length models
        without retained concrete-element metadata.
    """

    def rotate(self, n: int | z3.ArithRef) -> SymbolicList:
        """Return a rotated list, retaining concrete elements only for integer shifts."""
        this = cast("SymbolicList", self)
        if isinstance(n, int) and n == 0:
            return this

        idx = z3.Int(fresh_name("i"))

        safe_len = z3.If(this.z3_len == 0, ConstraintValues.int(1), this.z3_len)
        shift = n if isinstance(n, z3.ArithRef) else ConstraintValues.int(n)

        real_idx = ScalarValueOps.py_mod(idx - shift, safe_len)

        new_array = cast("z3.ArrayRef", z3.Lambda([idx], z3.Select(this.z3_array, real_idx)))

        new_concrete = None
        concrete_items = getattr(this, "_concrete_items", None)
        if concrete_items is not None and isinstance(n, int):
            import collections

            d = collections.deque(concrete_items)
            d.rotate(n)
            new_concrete = list(d)

        return type(this)(
            _name=f"{this.name}.rotate({n})",
            z3_array=new_array,
            z3_len=this.z3_len,
            element_type=this.element_type,
            _concrete_items=new_concrete,
        )

    def extend(self, other: SymbolicList | list[object] | tuple[object, ...]) -> SymbolicList:
        """Return an extended list built from concrete items or symbolic arrays."""
        this = cast("SymbolicList", self)
        if isinstance(other, (list, tuple)):
            res = this
            for item in other:
                s_item = item if isinstance(item, SymbolicValue) else SymbolicValue.from_const(item)
                res = res.append(s_item)
            return res
        other_concrete = getattr(other, "_concrete_items", None)
        if other_concrete is not None:
            res = this
            for item in other_concrete:
                s_item = item if isinstance(item, SymbolicValue) else SymbolicValue.from_const(item)
                res = res.append(s_item)
            return res
        idx = z3.Int(fresh_name("i"))
        new_array = cast(
            "z3.ArrayRef",
            z3.Lambda(
                [idx],
                z3.If(
                    idx < this.z3_len,
                    z3.Select(this.z3_array, idx),
                    z3.Select(other.z3_array, idx - this.z3_len),
                ),
            ),
        )
        return type(this)(
            _name=f"{this.name}.extend({other.name})",
            z3_array=new_array,
            z3_len=this.z3_len + other.z3_len,
            element_type=this.element_type,
        )

    def conditional_merge(
        self,
        other: object,
        condition: z3.BoolRef,
    ) -> SymbolicList | SymbolicValue:
        """Return a conditional value or list over both branch values.

        Notes:
            Matching Z3 fields are retained directly; a list result does not
            preserve concrete-element metadata.

        """
        this = cast("SymbolicList", self)
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

        are_lens_equal = this.z3_len is other.z3_len or Z3ExpressionOps.safe_eq(
            this.z3_len,
            other.z3_len,
        )
        new_len = this.z3_len if are_lens_equal else z3.If(condition, this.z3_len, other.z3_len)

        return type(this)(
            _name=f"If({condition}, {this.name}, {other.name})",
            z3_array=new_array,
            z3_len=new_len,
            element_type=this.element_type,
        )
