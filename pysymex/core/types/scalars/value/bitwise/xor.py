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

"""XOR and inversion operators for scalar symbolic values."""

from __future__ import annotations

from typing import cast

import z3

from pysymex.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex.core.solver.constraints.hashing import get_bitvec_val
from pysymex.core.types.scalars.value.helpers import (
    BV_WIDTH,
    Z3_OP_BXOR as _Z3_OP_BXOR,
    apply_concrete_integral_binary_op as _apply_concrete_integral_binary_op,
    apply_concrete_integral_unary_op as _apply_concrete_integral_unary_op,
    bv_to_int,
    int_to_bv,
)

from pysymex.core.types.scalars.value.protocols import SymbolicValueConstructor, SymbolicValueSelf


SymbolicValue = cast(SymbolicValueConstructor, object)


def _with_bitvector_cache(
    value: SymbolicValueSelf,
    bitvector: z3.ExprRef,
) -> SymbolicValueSelf:
    """Attach the exact bit-vector view used to build an integer bitwise result."""
    if z3.is_bv(bitvector):
        value._bv_cache = bitvector
    return value


def _nonnegative_int_bounds(value: SymbolicValueSelf) -> tuple[int, int] | None:
    """Return concrete non-negative integer bounds recorded on a value."""
    min_value = getattr(value, "min_val", None)
    max_value = getattr(value, "max_val", None)
    if not isinstance(min_value, int) or not isinstance(max_value, int):
        return None
    if min_value < 0 or max_value < min_value:
        return None
    return min_value, max_value


def _bounded_unsigned_xor(
    left: SymbolicValueSelf,
    right: SymbolicValueSelf,
) -> tuple[z3.ArithRef, int] | None:
    """Return an unsigned bounded XOR expression when operand bounds prove it sound."""
    left_bounds = _nonnegative_int_bounds(left)
    right_bounds = _nonnegative_int_bounds(right)
    if left_bounds is None or right_bounds is None:
        return None

    width = max(1, left_bounds[1].bit_length(), right_bounds[1].bit_length())
    left_bv = z3.Int2BV(left.z3_int, width)
    right_bv = z3.Int2BV(right.z3_int, width)
    return z3.BV2Int(left_bv ^ right_bv, is_signed=False), (1 << width) - 1


def bind_symbolic_value_class(value_cls: SymbolicValueConstructor) -> None:
    """Bind the concrete unified carrier constructed by XOR operations."""
    global SymbolicValue
    SymbolicValue = value_cls


class SymbolicValueBitwiseXorMixin:
    """Encode Boolean XOR or signed 64-bit integral bitwise operations."""

    def __xor__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Return Boolean XOR or bounded integer XOR with local expression folding."""
        concrete = _apply_concrete_integral_binary_op(self, other, lambda a, b: a ^ b)
        if concrete is not None:
            return concrete
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            bounded = _bounded_unsigned_xor(self, other)
            if bounded is not None:
                res_int, max_value = bounded
                return SymbolicValue(
                    _name=f"({self.name}^{other.name})",
                    z3_int=res_int,
                    is_int=Z3_TRUE,
                    z3_bool=Z3_FALSE,
                    is_bool=Z3_FALSE,
                    is_str=Z3_FALSE,
                    is_float=Z3_FALSE,
                    is_obj=Z3_FALSE,
                    is_list=Z3_FALSE,
                    is_dict=Z3_FALSE,
                    is_path=Z3_FALSE,
                    is_none=Z3_FALSE,
                    affinity_type="int",
                    min_val=0,
                    max_val=max_value,
                )

            left_bv = int_to_bv(self.z3_int)
            right_bv = int_to_bv(other.z3_int)
            if z3.eq(left_bv, right_bv):
                res_bv = get_bitvec_val(0, BV_WIDTH)
            elif left_bv.decl().kind() == _Z3_OP_BXOR and left_bv.num_args() == 2:
                a = left_bv.arg(0)
                b = left_bv.arg(1)
                if z3.eq(a, right_bv):
                    res_bv = b
                elif z3.eq(b, right_bv):
                    res_bv = a
                else:
                    res_bv = left_bv ^ right_bv
            elif right_bv.decl().kind() == _Z3_OP_BXOR and right_bv.num_args() == 2:
                a = right_bv.arg(0)
                b = right_bv.arg(1)
                if z3.eq(a, left_bv):
                    res_bv = b
                elif z3.eq(b, left_bv):
                    res_bv = a
                else:
                    res_bv = left_bv ^ right_bv
            else:
                res_bv = left_bv ^ right_bv
            return _with_bitvector_cache(
                SymbolicValue(
                    _name=f"({self.name}^{other.name})",
                    z3_int=bv_to_int(res_bv),
                    is_int=Z3_TRUE,
                    z3_bool=Z3_FALSE,
                    is_bool=Z3_FALSE,
                    is_str=Z3_FALSE,
                    is_float=Z3_FALSE,
                    is_obj=Z3_FALSE,
                    is_list=Z3_FALSE,
                    is_dict=Z3_FALSE,
                    is_path=Z3_FALSE,
                    is_none=Z3_FALSE,
                    affinity_type="int",
                ),
                res_bv,
            )

        if self_affinity == "bool" and other_affinity == "bool":
            return SymbolicValue(
                _name=f"({self.name}^{other.name})",
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=z3.Xor(self.z3_bool, other.z3_bool),
                is_bool=Z3_TRUE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
                affinity_type="bool",
            )

        left_bv = int_to_bv(self.z3_int)
        right_bv = int_to_bv(other.z3_int)
        if z3.eq(left_bv, right_bv):
            res_bv = get_bitvec_val(0, BV_WIDTH)
        elif left_bv.decl().kind() == _Z3_OP_BXOR and left_bv.num_args() == 2:
            a = left_bv.arg(0)
            b = left_bv.arg(1)
            if z3.eq(a, right_bv):
                res_bv = b
            elif z3.eq(b, right_bv):
                res_bv = a
            else:
                res_bv = left_bv ^ right_bv
        elif right_bv.decl().kind() == _Z3_OP_BXOR and right_bv.num_args() == 2:
            a = right_bv.arg(0)
            b = right_bv.arg(1)
            if z3.eq(a, left_bv):
                res_bv = b
            elif z3.eq(b, left_bv):
                res_bv = a
            else:
                res_bv = left_bv ^ right_bv
        else:
            res_bv = left_bv ^ right_bv
        is_int_res = z3.And(z3.Or(self.is_int, self.is_bool), z3.Or(other.is_int, other.is_bool))

        return _with_bitvector_cache(
            SymbolicValue(
                _name=f"({self.name}^{other.name})",
                z3_int=bv_to_int(res_bv),
                is_int=is_int_res,
                z3_bool=z3.Xor(self.z3_bool, other.z3_bool),
                is_bool=z3.And(self.is_bool, other.is_bool),
            ),
            res_bv,
        )

    def __rxor__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Reflected bitwise XOR operator."""

        return self.__xor__(other)

    def __invert__(self: SymbolicValueSelf) -> SymbolicValueSelf:
        """Return bounded signed-integer bitwise inversion for integral channels."""
        concrete = _apply_concrete_integral_unary_op(self, lambda a: ~a)
        if concrete is not None:
            return concrete
        self_affinity = self.affinity_type

        if self_affinity == "int":
            res_bv = ~int_to_bv(self.z3_int)
            res_int = bv_to_int(res_bv)
            return SymbolicValue(
                _name=f"(~{self.name})",
                z3_int=res_int,
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
                affinity_type="int",
            )

        res_bv = ~int_to_bv(self.z3_int)
        res_int = bv_to_int(res_bv)
        is_int_res = z3.simplify(z3.Or(self.is_int, self.is_bool))

        return SymbolicValue(
            _name=f"(~{self.name})",
            z3_int=res_int,
            is_int=is_int_res,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
        )
