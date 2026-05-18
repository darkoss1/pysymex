# pysymex: Python Symbolic Execution & Formal Verification
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

"""Lowering for comparison opcodes.

The lowerer encodes type case analysis in a single boolean expression and
separates TypeError reachability from the comparison result.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar, cast

import z3

from pysymex.core.types.scalars import (
    Z3_FALSE,
    Z3_TRUE,
    Z3_ZERO,
    SymbolicString,
    SymbolicValue,
)

if TYPE_CHECKING:
    from pysymex._typing import StackValue

_T = TypeVar("_T")


class ComparisonLowerer:
    """Translate Python comparisons to result and TypeError formulas."""

    def __init__(self, pc: int):
        self.pc = pc

    def lower(
        self, left: StackValue, right: StackValue, op: str
    ) -> tuple[SymbolicValue, z3.BoolRef]:
        """Lower a comparison to a (ResultValue, TypeErrorCondition) pair.

        ResultValue: A SymbolicValue containing the comparison result (bool).
        TypeErrorCondition: A Z3 boolean indicating if a TypeError should be raised.
        """
        if op.startswith("bool(") and op.endswith(")"):
            op = op[5:-1]

        s_left = self._to_symbolic(left)
        s_right = self._to_symbolic(right)

        res_bool, type_error_cond = self._emit_exhaustive_logic(s_left, s_right, op)

        result = SymbolicValue(
            _name=f"compare_{self.pc}",
            z3_int=z3.If(res_bool, z3.IntVal(1), Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=res_bool,
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )
        return result, type_error_cond

    def _to_symbolic(self, val: StackValue) -> SymbolicValue | SymbolicString:
        if isinstance(val, (SymbolicValue, SymbolicString)):
            return val
        if isinstance(val, str):
            return SymbolicString.from_const(val)
        return SymbolicValue.from_const(val)

    def _emit_exhaustive_logic(
        self,
        left: SymbolicValue | SymbolicString,
        right: SymbolicValue | SymbolicString,
        op: str,
    ) -> tuple[z3.BoolRef, z3.BoolRef]:
        """Generate unified formula for Result and TypeError."""
        fast_numeric = self._try_fast_numeric_compare(left, right, op)
        if fast_numeric is not None:
            return fast_numeric, Z3_FALSE

        l_is_int = self._get_attr(left, "is_int", Z3_FALSE)
        r_is_int = self._get_attr(right, "is_int", Z3_FALSE)
        l_is_float = self._get_attr(left, "is_float", Z3_FALSE)
        r_is_float = self._get_attr(right, "is_float", Z3_FALSE)
        l_is_bool = self._get_attr(left, "is_bool", Z3_FALSE)
        r_is_bool = self._get_attr(right, "is_bool", Z3_FALSE)
        l_is_str = self._get_attr(
            left, "is_str", Z3_TRUE if isinstance(left, SymbolicString) else Z3_FALSE
        )
        r_is_str = self._get_attr(
            right, "is_str", Z3_TRUE if isinstance(right, SymbolicString) else Z3_FALSE
        )

        l_num = z3.Or(l_is_int, l_is_float, l_is_bool)
        r_num = z3.Or(r_is_int, r_is_float, r_is_bool)

        both_num = z3.And(l_num, r_num)
        num_cmp = self._compare_numeric(op, left, right)

        both_str = z3.And(l_is_str, r_is_str)
        l_str = self._get_attr(left, "z3_str", z3.StringVal(""))
        r_str = self._get_attr(right, "z3_str", z3.StringVal(""))
        str_cmp = self._compare_strings(op, l_str, r_str)

        if op in ("==", "!="):
            type_error = Z3_FALSE
            mixed_cmp = Z3_FALSE if op == "==" else Z3_TRUE
        else:
            type_error = z3.Not(z3.Or(both_num, both_str))
            mixed_cmp = Z3_FALSE

        res_bool = z3.If(both_num, num_cmp, z3.If(both_str, str_cmp, mixed_cmp))

        return res_bool, type_error

    def _try_fast_numeric_compare(
        self,
        left: SymbolicValue | SymbolicString,
        right: SymbolicValue | SymbolicString,
        op: str,
    ) -> z3.BoolRef | None:
        """Compare known int/bool values without building exhaustive type formulas."""
        if not isinstance(left, SymbolicValue) or not isinstance(right, SymbolicValue):
            return None
        if left.affinity_type not in {"int", "bool"} or right.affinity_type not in {
            "int",
            "bool",
        }:
            return None

        left_expr = (
            z3.If(left.z3_bool, z3.IntVal(1), Z3_ZERO)
            if left.affinity_type == "bool"
            else left.z3_int
        )
        right_expr = (
            z3.If(right.z3_bool, z3.IntVal(1), Z3_ZERO)
            if right.affinity_type == "bool"
            else right.z3_int
        )
        return self._emit_rel(op, left_expr, right_expr)

    def _compare_numeric(
        self,
        op: str,
        left: SymbolicValue | SymbolicString,
        right: SymbolicValue | SymbolicString,
    ) -> z3.BoolRef:
        """Compare numeric values across Int, Float, and Bool encodings."""
        l_int = self._as_arith(self._get_attr(left, "z3_int", Z3_ZERO))
        r_int = self._as_arith(self._get_attr(right, "z3_int", Z3_ZERO))
        l_float = self._get_attr(left, "z3_float", z3.FPVal(0.0, z3.Float64()))
        r_float = self._get_attr(right, "z3_float", z3.FPVal(0.0, z3.Float64()))

        l_is_int = z3.Or(
            self._get_attr(left, "is_int", Z3_FALSE), self._get_attr(left, "is_bool", Z3_FALSE)
        )
        r_is_int = z3.Or(
            self._get_attr(right, "is_int", Z3_FALSE), self._get_attr(right, "is_bool", Z3_FALSE)
        )

        rm = z3.RoundNearestTiesToEven()
        sort = z3.Float64()

        l_to_fp = z3.fpToFP(rm, self._as_real(l_int), sort)
        r_to_fp = z3.fpToFP(rm, self._as_real(r_int), sort)

        int_int = self._emit_rel(op, l_int, r_int)
        fp_fp = self._emit_fp_rel(op, l_float, r_float)
        int_fp = self._emit_fp_rel(op, l_to_fp, r_float)
        fp_int = self._emit_fp_rel(op, l_float, r_to_fp)

        return z3.If(
            l_is_int,
            z3.If(r_is_int, int_int, int_fp),
            z3.If(r_is_int, fp_int, fp_fp),
        )

    def _emit_rel(self, op: str, left: z3.ArithRef, right: z3.ArithRef) -> z3.BoolRef:
        if op == "==":
            return left == right
        if op == "!=":
            return left != right
        if op == "<":
            return left < right
        if op == "<=":
            return left <= right
        if op == ">":
            return left > right
        if op == ">=":
            return left >= right
        return Z3_FALSE

    def _emit_fp_rel(self, op: str, left: z3.FPRef, right: z3.FPRef) -> z3.BoolRef:
        if op == "==":
            return z3.fpEQ(left, right)
        if op == "!=":
            return z3.Not(z3.fpEQ(left, right))
        if op == "<":
            return z3.fpLT(left, right)
        if op == "<=":
            return z3.fpLEQ(left, right)
        if op == ">":
            return z3.fpGT(left, right)
        if op == ">=":
            return z3.fpGEQ(left, right)
        return Z3_FALSE

    def _compare_strings(self, op: str, left: z3.SeqRef, right: z3.SeqRef) -> z3.BoolRef:
        if op == "==":
            return left == right
        if op == "!=":
            return left != right
        if op == "<":
            return left < right
        if op == "<=":
            return left <= right
        if op == ">":
            return left > right
        if op == ">=":
            return left >= right
        return Z3_FALSE

    def _get_attr(self, obj: object, name: str, default: _T) -> _T:
        return cast("_T", getattr(obj, name, default))

    def _as_arith(self, expr: object) -> z3.ArithRef:
        """Normalize non-arithmetic symbolic payloads away from numeric comparison paths."""
        if isinstance(expr, z3.ArithRef):
            return expr
        return Z3_ZERO

    def _as_real(self, expr: z3.ArithRef) -> z3.ArithRef:
        """Convert Int expressions to Real while leaving Real expressions unchanged."""
        if expr.is_int():
            return z3.ToReal(expr)
        return expr
