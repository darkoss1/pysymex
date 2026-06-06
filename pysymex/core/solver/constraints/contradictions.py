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

"""Fast contradiction checks for Z3 Boolean constraint lists."""

from __future__ import annotations

from collections import OrderedDict
import threading

import z3

from pysymex.core.cache.control import (
    is_process_cache_disabled,
    register_process_cache_clearer,
)
from pysymex.core.solver.constraints.hashing import ConstraintHasher, structural_hash
from pysymex.core.z3_utils import safe_z3_eq
from pysymex.logger import get_logger

_QUICK_CONTRADICTION_CACHE_MAX_SIZE = 4096
_QUICK_CONTRADICTION_HASHER = ConstraintHasher(max_cache_size=250_000)
_QUICK_CONTRADICTION_CACHE: OrderedDict[int, list[tuple[tuple[z3.BoolRef, ...], bool]]] = (
    OrderedDict()
)
_QUICK_CONTRADICTION_CACHE_LOCK = threading.RLock()
logger = get_logger(__name__)


def _same_constraint_sequence(left: tuple[z3.BoolRef, ...], right: list[z3.BoolRef]) -> bool:
    """Return True only for structurally identical Z3 constraint sequences."""
    if len(left) != len(right):
        return False
    for left_constraint, right_constraint in zip(left, right, strict=True):
        if left_constraint is right_constraint:
            continue
        if safe_z3_eq(left_constraint, right_constraint):
            continue
        if _QUICK_CONTRADICTION_HASHER.hash_expr(
            left_constraint
        ) != _QUICK_CONTRADICTION_HASHER.hash_expr(right_constraint):
            return False
        if not safe_z3_eq(left_constraint, right_constraint):
            return False
    return True


def _lookup_quick_contradiction_cache(cache_key: int, constraints: list[z3.BoolRef]) -> bool | None:
    """Return a cached answer only after structural sequence validation."""
    with _QUICK_CONTRADICTION_CACHE_LOCK:
        bucket = _QUICK_CONTRADICTION_CACHE.get(cache_key)
        if bucket is None:
            return None
        _QUICK_CONTRADICTION_CACHE.move_to_end(cache_key)
        for cached_constraints, cached_result in bucket:
            if _same_constraint_sequence(cached_constraints, constraints):
                if logger.state.trace_enabled:
                    logger.trace(
                        "Quick contradiction cache hit key=%d result=%s",
                        cache_key,
                        cached_result,
                    )
                return cached_result
    return None


def _store_quick_contradiction_cache(
    cache_key: int, constraints: list[z3.BoolRef], result: bool
) -> None:
    """Store one structurally checkable contradiction answer in the bounded LRU."""
    with _QUICK_CONTRADICTION_CACHE_LOCK:
        entry = (tuple(constraints), result)
        bucket = _QUICK_CONTRADICTION_CACHE.get(cache_key)
        if bucket is None:
            _QUICK_CONTRADICTION_CACHE[cache_key] = [entry]
        else:
            bucket.append(entry)
            _QUICK_CONTRADICTION_CACHE.move_to_end(cache_key)
        while len(_QUICK_CONTRADICTION_CACHE) > _QUICK_CONTRADICTION_CACHE_MAX_SIZE:
            _QUICK_CONTRADICTION_CACHE.popitem(last=False)


def _z3_decl_kind(expr: z3.ExprRef) -> int | None:
    """Return a Z3 declaration kind for application expressions."""
    try:
        return expr.decl().kind()
    except (AttributeError, z3.Z3Exception):
        if logger.state.debug_enabled:
            logger.debug(
                "Failed to read Z3 declaration kind for contradiction check", exc_info=True
            )
        return None


def quick_contradiction_check(constraints: list[z3.BoolRef]) -> bool:
    """Fast check for obvious contradictions without invoking the solver.

    Looks for explicit False values and direct negation pairs.
    It does not call ``z3.simplify()`` or establish general infeasibility.

    Uses a two-level approach to prevent false positives from hash collisions:
    1. Check for explicit ``False`` literals (O(n)).
    2. For each constraint ``c``, check whether ``Not(c)`` is structurally
       present in the list using Z3's ``ExprRef.eq()`` (structural equality),
       using the hash only as a pre-filter.

    Args:
        constraints: List of Z3 boolean constraints.

    Returns:
        True if a contradiction is detected, False otherwise.
    """
    if not constraints:
        return False

    has_not = False
    for c in constraints:
        kind = _z3_decl_kind(c)
        if kind == z3.Z3_OP_FALSE:
            return True
        if kind == z3.Z3_OP_NOT:
            has_not = True

    if not has_not:
        return False

    with _QUICK_CONTRADICTION_CACHE_LOCK:
        cache_key = structural_hash(constraints, _QUICK_CONTRADICTION_HASHER)
    cache_disabled = is_process_cache_disabled()
    if not cache_disabled:
        cached = _lookup_quick_contradiction_cache(cache_key, constraints)
        if cached is not None:
            return cached

    by_hash: dict[int, list[z3.BoolRef]] = {}
    for c in constraints:
        h = c.hash()
        bucket = by_hash.get(h)
        if bucket is None:
            by_hash[h] = [c]
        else:
            bucket.append(c)

    for c in constraints:
        if _z3_decl_kind(c) == z3.Z3_OP_NOT:
            arg = c.arg(0)
            arg_h = arg.hash()
            candidates = by_hash.get(arg_h)
            if candidates is None:
                continue
            for candidate in candidates:
                if arg is candidate or safe_z3_eq(arg, candidate):
                    if not cache_disabled:
                        _store_quick_contradiction_cache(cache_key, constraints, True)
                    return True

    if not cache_disabled:
        _store_quick_contradiction_cache(cache_key, constraints, False)
    return False


def clear_quick_contradiction_cache() -> None:
    """Clear cached quick-contradiction answers and helper hashes."""
    with _QUICK_CONTRADICTION_CACHE_LOCK:
        _QUICK_CONTRADICTION_CACHE.clear()
        _QUICK_CONTRADICTION_HASHER.clear()


register_process_cache_clearer(
    "core.quick_contradiction_cache",
    clear_quick_contradiction_cache,
)
