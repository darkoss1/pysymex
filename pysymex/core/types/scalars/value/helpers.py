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

"""Shared helpers for scalar symbolic values."""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import TYPE_CHECKING, Final

import z3

from pysymex.core.constants import Z3_ONE
from pysymex.core.types.base import fresh_name as _base_fresh_name
from pysymex.guards import is_list_of_objects as is_list_of_objects
from pysymex.logger import get_logger

FROM_CONST_CACHE_LIMIT: Final[int] = 512
SYMBOLIC_CACHE_LIMIT: Final[int] = 1024

logger = get_logger(__name__)

if TYPE_CHECKING:
    from pysymex.core.types.scalars.strings import SymbolicString as _SymbolicStringType
    from pysymex.core.types.scalars.values import SymbolicValue as _SymbolicValueType
else:
    _SymbolicStringType = object
    _SymbolicValueType = object

SymbolicValue = _SymbolicValueType
SymbolicString = _SymbolicStringType


def bind_scalar_value_classes(
    value_cls: type[_SymbolicValueType], string_cls: type[_SymbolicStringType]
) -> None:
    """Bind carrier classes needed by scalar helper predicates."""
    global SymbolicValue, SymbolicString
    SymbolicValue = value_cls
    SymbolicString = string_cls


_FROM_CONST_CACHE_LOCK = threading.Lock()

_BV_WIDTH: int = 64
_Z3_OP_BV2INT: int = int(getattr(z3, "Z3_OP_BV2INT", -1))
_Z3_OP_BXOR: int = int(getattr(z3, "Z3_OP_BXOR", -1))

fresh_name = _base_fresh_name


def exactly_one_bool(type_vars: list[z3.BoolRef]) -> z3.BoolRef:
    """Return the pseudo-Boolean constraint requiring one active type flag."""
    return z3.PbEq([(type_var, 1) for type_var in type_vars], 1)


def _int_to_bv(expr: z3.ArithRef) -> z3.BitVecRef:
    """Convert or normalize an integer expression into a signed 64-bit view."""
    try:
        if expr.decl().kind() == _Z3_OP_BV2INT and expr.num_args() == 1:
            underlying_bv = expr.arg(0)
            if z3.is_bv(underlying_bv):
                width = underlying_bv.size()
                if width == _BV_WIDTH:
                    return underlying_bv
                if width < _BV_WIDTH:
                    return z3.SignExt(_BV_WIDTH - width, underlying_bv)
                return z3.Extract(_BV_WIDTH - 1, 0, underlying_bv)
    except (AttributeError, z3.Z3Exception):
        logger.debug("Z3 bv2int reuse path unavailable; using Int2BV", exc_info=True)
    return z3.Int2BV(expr, _BV_WIDTH)


def _bv_to_int(expr: z3.ExprRef) -> z3.ArithRef:
    """Return the signed integer interpretation of a bit-vector expression."""
    if not z3.is_bv(expr):
        raise TypeError("Expected BitVecRef expression")
    return z3.BV2Int(expr, is_signed=True)


FROM_CONST_CACHE: dict[str | tuple[str, int] | tuple[str, float], object] = {}

STRING_CONST_CACHE: dict[str, object] = {}
STRING_CONST_CACHE_LOCK = threading.Lock()
STRING_CONST_CACHE_LIMIT: int = 2048

SYMBOLIC_CACHE: dict[str, tuple[object, z3.BoolRef]] = {}

int_to_bv = _int_to_bv
bv_to_int = _bv_to_int
BV_WIDTH: int = _BV_WIDTH
Z3_OP_BV2INT: int = _Z3_OP_BV2INT
Z3_OP_BXOR: int = _Z3_OP_BXOR


def _cached_int_value_is_usable(value: object) -> bool:
    """Return whether a cached carrier still exposes an integer-sort payload."""
    try:
        z3_int = getattr(value, "z3_int", None)
        if not isinstance(z3_int, z3.ArithRef):
            return False
        return z3_int.sort().kind() == z3.Z3_INT_SORT
    except z3.Z3Exception:
        return False


def _next_address() -> int:
    """Resolve the shared address counter lazily to avoid import cycles."""
    from pysymex.core.identity.addressing import next_address

    return next_address()


def _guarded_nonzero_divisor(divisor: z3.ArithRef) -> z3.ArithRef:
    """Replace a symbolic zero-divisor branch with integer one.

    Limitations:
        This prevents undefined arithmetic in an expression; it does not
        preserve or emit a Python zero-division exception path.
    """
    return z3.If(divisor == 0, Z3_ONE, divisor)


def _py_floor_div(a: z3.ArithRef, b: z3.ArithRef) -> z3.ArithRef:
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


def _py_mod(a: z3.ArithRef, b: z3.ArithRef) -> z3.ArithRef:
    """Return modulo derived from modeled Python floor division for nonzero ``b``."""
    q = _py_floor_div(a, b)
    return a - (b * q)


py_floor_div = _py_floor_div
py_mod = _py_mod
FROM_CONST_CACHE_LOCK = _FROM_CONST_CACHE_LOCK
next_address = _next_address
guarded_nonzero_divisor = _guarded_nonzero_divisor


def is_concrete_val(v: object) -> bool:
    """Return whether ``v`` has a retained concrete payload when specialized."""
    if isinstance(v, (SymbolicValue, SymbolicString)):
        return getattr(v, "_constant_value", None) is not None
    return True


def _extract_concrete_numeric(value: object) -> int | float | bool | None:
    """Extract a concrete numeric payload when available."""
    if isinstance(value, SymbolicValue):
        payload = value.value
    else:
        payload = value
    if isinstance(payload, (int, float, bool)):
        return payload
    return None


def _extract_concrete_integral(value: object) -> int | None:
    """Extract a concrete integral payload for bitwise Python operations."""
    payload = _extract_concrete_numeric(value)
    if isinstance(payload, float):
        return None
    if isinstance(payload, bool):
        return int(payload)
    return payload


def _concrete_numeric_is_nonzero(value: object) -> bool:
    """Return whether *value* is a concrete numeric payload known to be nonzero."""
    return isinstance(value, (int, float, bool)) and value != 0


def _apply_concrete_numeric_binary_op(
    left: object,
    right: object,
    op: Callable[[int | float | bool, int | float | bool], object],
) -> _SymbolicValueType | None:
    """Execute concrete numeric operation eagerly using Python semantics."""
    left_num = _extract_concrete_numeric(left)
    right_num = _extract_concrete_numeric(right)
    if left_num is None or right_num is None:
        return None
    return SymbolicValue.from_const(op(left_num, right_num))


def _apply_concrete_integral_binary_op(
    left: object,
    right: object,
    op: Callable[[int, int], object],
) -> _SymbolicValueType | None:
    """Execute a concrete integral operation eagerly using Python semantics."""
    left_num = _extract_concrete_integral(left)
    right_num = _extract_concrete_integral(right)
    if left_num is None or right_num is None:
        return None
    return SymbolicValue.from_const(op(left_num, right_num))


def _apply_concrete_integral_unary_op(
    value: object,
    op: Callable[[int], object],
) -> _SymbolicValueType | None:
    """Execute a unary concrete integral operation eagerly."""
    payload = _extract_concrete_integral(value)
    if payload is None:
        return None
    return SymbolicValue.from_const(op(payload))


cached_int_value_is_usable = _cached_int_value_is_usable
extract_concrete_numeric = _extract_concrete_numeric
extract_concrete_integral = _extract_concrete_integral
concrete_numeric_is_nonzero = _concrete_numeric_is_nonzero
apply_concrete_numeric_binary_op = _apply_concrete_numeric_binary_op
apply_concrete_integral_binary_op = _apply_concrete_integral_binary_op
apply_concrete_integral_unary_op = _apply_concrete_integral_unary_op
