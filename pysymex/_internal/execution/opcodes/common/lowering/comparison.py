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

"""Lower ``COMPARE_OP`` to Z3 boolean expressions with CPython type-case structure.

Encodes mixed-type comparisons, ``is`` / ``is not``, and exception-type checks in one
formula, tracking separate TypeError feasibility from the comparison truth value. Used by
version ``compare`` opcode modules and membership lowering.

Limitations:
    Custom rich comparison on incompletely modeled objects may degrade to unsupported
    abstraction tags instead of full dunder dispatch.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar, cast

import z3

from pysymex._internal.core.constants import (
    Z3_EMPTY_BYTES,
    Z3_EMPTY_STRING,
    Z3_FALSE,
    Z3_ONE,
    Z3_TRUE,
    Z3_ZERO,
)
from pysymex._internal.core.solver.constraints.literals import exact_bool_literal
from pysymex._internal.core.types.affinity import AffinityKind
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.numeric.float import SymbolicFloat
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue

BYTES_ORDER_MAX_UNROLL = 32

if TYPE_CHECKING:
    from pysymex._internal.typing.protocols import StackValue

_T = TypeVar("_T")


class ComparisonLowerer:
    """Translate Python comparisons to result and TypeError formulas."""

    def __init__(self, pc: int) -> None:
        """Record the bytecode offset used for comparison lowering."""
        self.pc = pc

    def lower(
        self,
        left: StackValue,
        right: StackValue,
        op: str,
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
            z3_int=z3.If(res_bool, Z3_ONE, Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=res_bool,
            is_bool=Z3_TRUE,
            affinity_type=AffinityKind.BOOL,
        )
        return result, type_error_cond

    def _to_symbolic(self, val: StackValue) -> SymbolicValue | SymbolicString | SymbolicBytes:
        """Normalize a stack operand to symbolic scalar, string, or bytes form."""
        if isinstance(val, SymbolicValue):
            if isinstance(val.value, bytes):
                return SymbolicBytes.concrete(val.value)
            return val
        if isinstance(val, (SymbolicString, SymbolicBytes)):
            return val
        if isinstance(val, SymbolicFloat):
            return SymbolicValue(
                _name=val.name,
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                z3_float=val.z3_expr,
                is_float=Z3_TRUE,
                affinity_type=AffinityKind.FLOAT,
            )
        if isinstance(val, str):
            return SymbolicString.from_const(val)
        if isinstance(val, bytes):
            return SymbolicBytes.concrete(val)
        return SymbolicValue.from_const(val)

    def _emit_exhaustive_logic(
        self,
        left: SymbolicValue | SymbolicString | SymbolicBytes,
        right: SymbolicValue | SymbolicString | SymbolicBytes,
        op: str,
    ) -> tuple[z3.BoolRef, z3.BoolRef]:
        """Generate unified formula for Result and TypeError."""
        fast_bytes = self._try_fast_bytes_compare(left, right, op)
        if fast_bytes is not None:
            return fast_bytes, Z3_FALSE

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
            left,
            "is_str",
            Z3_TRUE if isinstance(left, SymbolicString) else Z3_FALSE,
        )
        r_is_str = self._get_attr(
            right,
            "is_str",
            Z3_TRUE if isinstance(right, SymbolicString) else Z3_FALSE,
        )
        l_is_bytes = self._get_attr(
            left,
            "is_bytes",
            Z3_TRUE if isinstance(left, SymbolicBytes) else Z3_FALSE,
        )
        r_is_bytes = self._get_attr(
            right,
            "is_bytes",
            Z3_TRUE if isinstance(right, SymbolicBytes) else Z3_FALSE,
        )

        l_num = z3.Or(l_is_int, l_is_float, l_is_bool)
        r_num = z3.Or(r_is_int, r_is_float, r_is_bool)

        both_num = z3.And(l_num, r_num)
        num_cmp = self._compare_numeric(op, left, right)

        both_str = z3.And(l_is_str, r_is_str)
        l_str = self._get_attr(left, "z3_str", Z3_EMPTY_STRING)
        r_str = self._get_attr(right, "z3_str", Z3_EMPTY_STRING)
        str_cmp = self._compare_strings(op, l_str, r_str)
        both_bytes = z3.And(l_is_bytes, r_is_bytes)
        l_bytes = self._get_attr(left, "z3_bytes", Z3_EMPTY_BYTES)
        r_bytes = self._get_attr(right, "z3_bytes", Z3_EMPTY_BYTES)
        bytes_cmp = self._compare_bytes(op, l_bytes, r_bytes)

        if op in ("==", "!="):
            type_error = Z3_FALSE
            mixed_cmp = Z3_FALSE if op == "==" else Z3_TRUE
        else:
            type_error = z3.Not(z3.Or(both_num, both_str, both_bytes))
            mixed_cmp = Z3_FALSE

        res_bool = z3.If(
            both_num,
            num_cmp,
            z3.If(both_str, str_cmp, z3.If(both_bytes, bytes_cmp, mixed_cmp)),
        )

        return res_bool, type_error

    def _try_fast_bytes_compare(
        self,
        left: SymbolicValue | SymbolicString | SymbolicBytes,
        right: SymbolicValue | SymbolicString | SymbolicBytes,
        op: str,
    ) -> z3.BoolRef | None:
        """Compare bytes sequences without erasing them to opaque object carriers."""
        if not isinstance(left, SymbolicBytes) or not isinstance(right, SymbolicBytes):
            return None
        return self._compare_bytes(op, left.z3_bytes, right.z3_bytes, left=left, right=right)

    def _compare_bytes(
        self,
        op: str,
        left_expr: z3.SeqRef,
        right_expr: z3.SeqRef,
        *,
        left: SymbolicBytes | None = None,
        right: SymbolicBytes | None = None,
    ) -> z3.BoolRef:
        """Emit CPython bytes comparison semantics where precision is tractable."""
        if op == "==":
            return left_expr == right_expr
        if op == "!=":
            return left_expr != right_expr

        less_than = self._compare_bytes_less_than(left_expr, right_expr, left=left, right=right)
        if op == "<":
            return less_than
        if op == "<=":
            return z3.Or(less_than, left_expr == right_expr)
        if op == ">":
            return self._compare_bytes_less_than(right_expr, left_expr, left=right, right=left)
        if op == ">=":
            return z3.Or(
                self._compare_bytes_less_than(right_expr, left_expr, left=right, right=left),
                left_expr == right_expr,
            )
        return Z3_FALSE

    def _compare_bytes_less_than(
        self,
        left_expr: z3.SeqRef,
        right_expr: z3.SeqRef,
        *,
        left: SymbolicBytes | None = None,
        right: SymbolicBytes | None = None,
    ) -> z3.BoolRef:
        """Return lexicographic ``left < right`` for bytes.

        Concrete payloads and bounded known-length symbolic byte sequences are
        unrolled to quantifier-free constraints. Unknown-length symbolic
        sequences use the exact lexicographic existential definition.
        """
        if left is not None and right is not None:
            left_concrete = left.concrete_value
            right_concrete = right.concrete_value
            if left_concrete is not None and right_concrete is not None:
                return Z3_TRUE if left_concrete < right_concrete else Z3_FALSE
            left_len = _literal_int(left.z3_len)
            right_len = _literal_int(right.z3_len)
        else:
            left_len = _literal_int(z3.Length(left_expr))
            right_len = _literal_int(z3.Length(right_expr))

        if (
            left_len is not None
            and right_len is not None
            and 0 <= left_len <= BYTES_ORDER_MAX_UNROLL
            and 0 <= right_len <= BYTES_ORDER_MAX_UNROLL
        ):
            min_len = min(left_len, right_len)
            cases: list[z3.BoolRef] = []
            for index in range(min_len):
                prefix_equal = [left_expr[i] == right_expr[i] for i in range(index)]
                cases.append(z3.And(*prefix_equal, z3.ULT(left_expr[index], right_expr[index])))
            if left_len < right_len:
                prefix_equal = [left_expr[i] == right_expr[i] for i in range(min_len)]
                cases.append(z3.And(*prefix_equal))
            if not cases:
                return Z3_FALSE
            return z3.Or(*cases)

        index = z3.Int(f"bytes_order_{self.pc}_idx")
        left_len_expr = z3.Length(left_expr)
        right_len_expr = z3.Length(right_expr)
        first_difference = z3.Exists(
            [index],
            z3.And(
                index >= 0,
                index < left_len_expr,
                index < right_len_expr,
                z3.SubSeq(left_expr, 0, index) == z3.SubSeq(right_expr, 0, index),
                z3.ULT(left_expr[index], right_expr[index]),
            ),
        )
        proper_prefix = z3.And(
            left_len_expr < right_len_expr,
            z3.SubSeq(left_expr, 0, left_len_expr) == z3.SubSeq(right_expr, 0, left_len_expr),
        )
        return z3.Or(first_difference, proper_prefix)

    def _try_fast_numeric_compare(
        self,
        left: SymbolicValue | SymbolicString | SymbolicBytes,
        right: SymbolicValue | SymbolicString | SymbolicBytes,
        op: str,
    ) -> z3.BoolRef | None:
        """Compare known int/bool values without building exhaustive type formulas."""
        if not isinstance(left, SymbolicValue) or not isinstance(right, SymbolicValue):
            return None
        left_expr = self._definite_int_or_bool_expr(left)
        right_expr = self._definite_int_or_bool_expr(right)
        if left_expr is None or right_expr is None:
            return None

        return self._emit_rel(op, left_expr, right_expr)

    def _definite_int_or_bool_expr(self, value: SymbolicValue) -> z3.ArithRef | None:
        """Return the arithmetic payload for definitely int/bool carriers."""
        if value.affinity_type == AffinityKind.BOOL or _is_literal_true(value.is_bool):
            return z3.If(value.z3_bool, Z3_ONE, Z3_ZERO)
        if value.affinity_type == AffinityKind.INT:
            return value.z3_int
        if not _is_literal_true(value.is_int):
            return None
        if any(
            _is_literal_true(flag)
            for flag in (
                value.is_float,
                value.is_str,
                value.is_obj,
                value.is_list,
                value.is_dict,
                value.is_path,
                value.is_none,
            )
        ):
            return None
        return value.z3_int

    def _compare_numeric(
        self,
        op: str,
        left: SymbolicValue | SymbolicString | SymbolicBytes,
        right: SymbolicValue | SymbolicString | SymbolicBytes,
    ) -> z3.BoolRef:
        """Compare numeric values across Int, Float, and Bool encodings."""
        l_int = self._as_arith(self._get_attr(left, "z3_int", Z3_ZERO))
        r_int = self._as_arith(self._get_attr(right, "z3_int", Z3_ZERO))
        l_float = self._get_attr(left, "z3_float", z3.FPVal(0.0, z3.Float64()))
        r_float = self._get_attr(right, "z3_float", z3.FPVal(0.0, z3.Float64()))

        l_is_int = z3.Or(
            self._get_attr(left, "is_int", Z3_FALSE),
            self._get_attr(left, "is_bool", Z3_FALSE),
        )
        r_is_int = z3.Or(
            self._get_attr(right, "is_int", Z3_FALSE),
            self._get_attr(right, "is_bool", Z3_FALSE),
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
        """Emit a Z3 integer relational comparison for *op*."""
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
        """Emit a Z3 floating-point relational comparison for *op*."""
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
        """Emit a Z3 sequence relational comparison for string operands."""
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
        """Read attribute *name* from *obj*, falling back to *default*."""
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


def _literal_int(expression: z3.ArithRef) -> int | None:
    """Return a concrete integer value without invoking the solver."""
    if z3.is_int_value(expression):
        return expression.as_long()
    return None


def _is_literal_true(expression: z3.BoolRef) -> bool:
    """Return whether *expression* is definitely true without solver simplification."""
    return exact_bool_literal(expression) is True
