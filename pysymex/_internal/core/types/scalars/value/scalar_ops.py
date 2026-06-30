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

"""Scalar value operations, caches, and Z3 arithmetic helpers."""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Final

import z3

from pysymex._internal.core.constants import Z3_ONE
from pysymex._internal.core.types.capabilities import has_retained_concrete_value
from pysymex._internal.core.types.scalars.value.protocols import (
    ValueConstructor,
    unbound_symbolic_value_constructor,
)
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.core.types.scalars.values import SymbolicValue

FROM_CONST_CACHE_LIMIT: Final[int] = 512

logger = get_logger(__name__)

_symbolic_value_cls = unbound_symbolic_value_constructor()
_symbolic_string_cls: type[object] = object


def bind_scalar_value_classes(value_cls: ValueConstructor, string_cls: type[object]) -> None:
    """Bind carrier classes needed by scalar helper predicates."""
    global _symbolic_value_cls, _symbolic_string_cls
    _symbolic_value_cls = value_cls
    _symbolic_string_cls = string_cls


FROM_CONST_CACHE_LOCK = threading.Lock()

BV_WIDTH: int = 64
Z3_OP_BV2INT: int = int(getattr(z3, "Z3_OP_BV2INT", -1))
Z3_OP_BXOR: int = int(getattr(z3, "Z3_OP_BXOR", -1))

FROM_CONST_CACHE: dict[str | tuple[str, int] | tuple[str, float], object] = {}

STRING_CONST_CACHE: dict[str, object] = {}
STRING_CONST_CACHE_LOCK = threading.Lock()
STRING_CONST_CACHE_LIMIT: int = 2048

SYMBOLIC_CACHE: dict[str, tuple[object, z3.BoolRef]] = {}


class ScalarValueOps:
    """Domain owner for scalar Z3 arithmetic and concrete-value extraction."""

    @staticmethod
    def exactly_one_bool(type_vars: list[z3.BoolRef]) -> z3.BoolRef:
        """Return the pseudo-Boolean constraint requiring one active type flag."""
        return z3.PbEq([(type_var, 1) for type_var in type_vars], 1)

    @staticmethod
    def int_to_bv(expr: z3.ArithRef) -> z3.BitVecRef:
        """Convert or normalize an integer expression into a signed 64-bit view."""
        try:
            if expr.decl().kind() == Z3_OP_BV2INT and expr.num_args() == 1:
                underlying_bv = expr.arg(0)
                if z3.is_bv(underlying_bv):
                    width = underlying_bv.size()
                    if width == BV_WIDTH:
                        return underlying_bv
                    if width < BV_WIDTH:
                        return z3.SignExt(BV_WIDTH - width, underlying_bv)
                    return z3.Extract(BV_WIDTH - 1, 0, underlying_bv)
        except (AttributeError, z3.Z3Exception):
            logger.debug("Z3 bv2int reuse path unavailable; using Int2BV", exc_info=True)
        return z3.Int2BV(expr, BV_WIDTH)

    @staticmethod
    def bv_to_int(expr: z3.ExprRef) -> z3.ArithRef:
        """Return the signed integer interpretation of a bit-vector expression."""
        if not z3.is_bv(expr):
            msg = "Expected BitVecRef expression"
            raise TypeError(msg)
        return z3.BV2Int(expr, is_signed=True)

    @staticmethod
    def guarded_nonzero_divisor(divisor: z3.ArithRef) -> z3.ArithRef:
        """Replace a symbolic zero-divisor branch with integer one.

        Limitations:
            This prevents undefined arithmetic in an expression; it does not
            preserve or emit a Python zero-division exception path.
        """
        return z3.If(divisor == 0, Z3_ONE, divisor)

    @staticmethod
    def py_floor_div(a: z3.ArithRef, b: z3.ArithRef) -> z3.ArithRef:
        """Return Python-compatible floor division when ``b`` is nonzero.

        Python's ``//`` rounds toward negative infinity. Z3's integer ``/``
        uses Euclidean division (remainder always >= 0), which matches Python
        when ``b > 0`` but differs by 1 when ``b < 0`` and the remainder is
        non-zero.  Correct by subtracting 1 in that case.
        """
        return z3.If(
            b > 0,
            a / b,
            z3.If(a % b == 0, a / b, a / b - 1),
        )

    @staticmethod
    def py_mod(a: z3.ArithRef, b: z3.ArithRef) -> z3.ArithRef:
        """Return modulo derived from modeled Python floor division for nonzero ``b``."""
        q = ScalarValueOps.py_floor_div(a, b)
        return a - (b * q)

    @staticmethod
    def is_concrete_val(v: object) -> bool:
        """Return whether ``v`` has a retained concrete payload when specialized."""
        return has_retained_concrete_value(v)

    @staticmethod
    def extract_concrete_numeric(value: object) -> int | float | bool | None:
        """Extract a concrete numeric payload when available."""
        from pysymex._internal.core.types.scalars.values import SymbolicValue

        payload = value.value if isinstance(value, SymbolicValue) else value
        if isinstance(payload, (int, float, bool)):
            return payload
        return None

    @staticmethod
    def extract_concrete_integral(value: object) -> int | None:
        """Extract a concrete integral payload for bitwise Python operations."""
        payload = ScalarValueOps.extract_concrete_numeric(value)
        if isinstance(payload, float):
            return None
        if isinstance(payload, bool):
            return int(payload)
        return payload

    @staticmethod
    def concrete_numeric_is_nonzero(value: object) -> bool:
        """Return whether *value* is a concrete numeric payload known to be nonzero."""
        return isinstance(value, (int, float, bool)) and value != 0

    @staticmethod
    def apply_concrete_numeric_binary_op(
        left: object,
        right: object,
        op: Callable[[int | float | bool, int | float | bool], object],
    ) -> SymbolicValue | None:
        """Execute concrete numeric operation eagerly using Python semantics."""
        left_num = ScalarValueOps.extract_concrete_numeric(left)
        right_num = ScalarValueOps.extract_concrete_numeric(right)
        if left_num is None or right_num is None:
            return None
        return _symbolic_value_cls.from_const(op(left_num, right_num))

    @staticmethod
    def apply_concrete_integral_binary_op(
        left: object,
        right: object,
        op: Callable[[int, int], object],
    ) -> SymbolicValue | None:
        """Execute a concrete integral operation eagerly using Python semantics."""
        left_num = ScalarValueOps.extract_concrete_integral(left)
        right_num = ScalarValueOps.extract_concrete_integral(right)
        if left_num is None or right_num is None:
            return None
        return _symbolic_value_cls.from_const(op(left_num, right_num))

    @staticmethod
    def apply_concrete_integral_unary_op(
        value: object,
        op: Callable[[int], object],
    ) -> SymbolicValue | None:
        """Execute a unary concrete integral operation eagerly."""
        payload = ScalarValueOps.extract_concrete_integral(value)
        if payload is None:
            return None
        return _symbolic_value_cls.from_const(op(payload))
