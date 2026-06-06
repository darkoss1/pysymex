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

"""Cheap SMT-theory probes used before expensive solver queries."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable

import z3

from pysymex.core.cache.control import (
    is_process_cache_disabled,
    register_process_cache_clearer,
)
from pysymex.core.z3_utils import safe_z3_eq
from pysymex.logger import get_logger

logger = get_logger(__name__)

_BitvectorTheoryCacheKey = tuple[int, int]
_BITVECTOR_THEORY_CACHE_MAX_SIZE = 8192
_BITVECTOR_THEORY_CACHE: OrderedDict[
    _BitvectorTheoryCacheKey,
    tuple[z3.ExprRef, bool],
] = OrderedDict()


def is_complex_smt_theory(expr: object) -> bool:
    """Return whether a Z3 expression involves complex SMT theories."""
    if not isinstance(expr, z3.ExprRef):
        return False

    if isinstance(expr, (z3.FPRef, z3.ArrayRef, z3.BitVecRef)):
        return True

    try:
        decl = expr.decl()
        kind = decl.kind()
        name = str(decl.name()).lower()
    except (AttributeError, z3.Z3Exception):
        return False

    if kind in (z3.Z3_OP_DIV, z3.Z3_OP_MOD) or name in ("div", "mod", "rem"):
        return True

    if kind == z3.Z3_OP_MUL:
        try:
            non_const_count = 0
            for child in expr.children():
                if not isinstance(child, (z3.IntNumRef, z3.RatNumRef)):
                    non_const_count += 1
            if non_const_count > 1:
                return True
        except (AttributeError, z3.Z3Exception):
            logger.trace("SMT complexity probe failed on multiply expression", exc_info=True)

    try:
        children = expr.children()
    except (AttributeError, z3.Z3Exception):
        return False

    return any(is_complex_smt_theory(child) for child in children)


def is_bitvector_smt_theory(expr: object) -> bool:
    """Return whether a Z3 expression contains bit-vector theory terms."""
    if not isinstance(expr, z3.ExprRef):
        return False
    if is_process_cache_disabled():
        return _uncached_is_bitvector_smt_theory(expr)
    return _cached_is_bitvector_smt_theory(expr)


def constraints_include_bitvector_smt_theory(constraints: Iterable[object]) -> bool:
    """Return whether any path constraint contains bit-vector theory terms."""
    return any(is_bitvector_smt_theory(constraint) for constraint in constraints)


def constraints_include_complex_smt_theory(constraints: Iterable[object]) -> bool:
    """Return whether any path constraint contains solver-expensive SMT theory terms."""
    return any(is_complex_smt_theory(constraint) for constraint in constraints)


def clear_bitvector_theory_cache() -> None:
    """Clear process-wide bit-vector theory probe results."""
    _BITVECTOR_THEORY_CACHE.clear()


register_process_cache_clearer(
    "core.bitvector_theory_cache",
    clear_bitvector_theory_cache,
)


def _cached_is_bitvector_smt_theory(expr: z3.ExprRef) -> bool:
    cache_key = _bitvector_theory_cache_key(expr)
    cached = _BITVECTOR_THEORY_CACHE.get(cache_key)
    if cached is not None:
        cached_expr, cached_result = cached
        if cached_expr is expr or safe_z3_eq(cached_expr, expr):
            _BITVECTOR_THEORY_CACHE.move_to_end(cache_key)
            return cached_result
        del _BITVECTOR_THEORY_CACHE[cache_key]

    result = _uncached_is_bitvector_smt_theory(expr)
    _BITVECTOR_THEORY_CACHE[cache_key] = (expr, result)
    if len(_BITVECTOR_THEORY_CACHE) > _BITVECTOR_THEORY_CACHE_MAX_SIZE:
        _BITVECTOR_THEORY_CACHE.popitem(last=False)
    return result


def _bitvector_theory_cache_key(expr: z3.ExprRef) -> _BitvectorTheoryCacheKey:
    return (id(expr.ctx_ref()), expr.get_id())


def _uncached_is_bitvector_smt_theory(expr: z3.ExprRef) -> bool:
    if isinstance(expr, z3.BitVecRef):
        return True

    try:
        children = expr.children()
    except (AttributeError, z3.Z3Exception):
        return False

    return any(is_bitvector_smt_theory(child) for child in children)


__all__ = [
    "clear_bitvector_theory_cache",
    "constraints_include_bitvector_smt_theory",
    "constraints_include_complex_smt_theory",
    "is_bitvector_smt_theory",
    "is_complex_smt_theory",
]
