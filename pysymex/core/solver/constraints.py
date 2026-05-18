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

"""Constraint utilities for pysymex.

Provides:
- Structural hashing for Z3 constraints using native AST-based hashing
- Theory-aware constraint simplification and optimization
"""

from __future__ import annotations

from collections import OrderedDict
from typing import cast
import weakref

import z3

from pysymex.contracts.decorators import ensures, requires
from pysymex.core.types.base import safe_z3_eq

_INT_CACHE: dict[int, z3.IntNumRef] = {}


def _is_z3_expr(value: object) -> bool:
    return isinstance(value, z3.ExprRef)


def _is_z3_bool_list(value: object) -> bool:
    return isinstance(value, list) and all(
        isinstance(item, z3.BoolRef) for item in cast("list[object]", value)
    )


def _is_z3_expr_list(value: object) -> bool:
    return isinstance(value, list) and all(
        isinstance(item, z3.ExprRef) for item in cast("list[object]", value)
    )


def _is_z3_expr_or_bool_list(value: object) -> bool:
    return _is_z3_bool_list(value) or _is_z3_expr_list(value)


def _is_positive_int(value: object) -> bool:
    return isinstance(value, int) and value > 0


def _is_int(value: object) -> bool:
    return isinstance(value, int)


def _is_non_negative_int(value: object) -> bool:
    return isinstance(value, int) and value >= 0


@requires("val == val")
def get_int_val(val: int) -> z3.IntNumRef:
    """Return a cached Z3 integer constant."""
    if val in _INT_CACHE:
        return _INT_CACHE[val]
    z3_val = z3.IntVal(val)
    if -256 <= val <= 2048:
        _INT_CACHE[val] = z3_val
    return z3_val


class ConstraintHasher:
    """Stateful hasher for Z3 expressions with id-reuse protection."""

    @requires(_is_positive_int)
    def __init__(self, max_cache_size: int = 1_000_000) -> None:
        """Initialize a new constraint hasher with empty cache.

        Args:
            max_cache_size: Maximum number of cached expression ids before
                the cache is cleared to avoid long-lived stale-id reuse.
        """
        if max_cache_size <= 0:
            raise ValueError("max_cache_size must be > 0")
        self._cache: dict[int, tuple[weakref.ReferenceType[z3.ExprRef], int]] = {}
        self._max_cache_size = max_cache_size

    def clear(self) -> None:
        """Clear the internal id->hash cache."""
        self._cache.clear()

    @ensures(_is_non_negative_int)
    def cache_size(self) -> int:
        """Return the current number of cached expression hashes."""
        self._prune_dead_entries()
        return len(self._cache)

    def _prune_dead_entries(self) -> None:
        """Remove entries whose Z3 wrapper has been garbage-collected."""
        stale_ids: list[int] = [
            expr_id for expr_id, (expr_ref, _) in self._cache.items() if expr_ref() is None
        ]
        for expr_id in stale_ids:
            del self._cache[expr_id]

    @requires(_is_z3_expr)
    @ensures(_is_int)
    def hash_expr(self, constraint: z3.ExprRef) -> int:
        """Return a cached structural hash for a single Z3 expression."""
        h: int | None = getattr(constraint, "_symex_hash", None)
        if h is not None:
            return h

        constraint_id = id(constraint)
        cached = self._cache.get(constraint_id)
        if cached is not None:
            cached_expr, cached_hash = cached
            if cached_expr() is constraint:
                return cached_hash

        if len(self._cache) >= self._max_cache_size:
            self._prune_dead_entries()
        if len(self._cache) >= self._max_cache_size:
            self._cache.clear()
        computed = constraint.hash()
        self._cache[constraint_id] = (weakref.ref(constraint), computed)

        try:
            setattr(constraint, "_symex_hash", computed)
        except AttributeError:
            return computed
        return computed

    @requires(_is_z3_expr_or_bool_list)
    @ensures(_is_int)
    def structural_hash(self, constraints: list[z3.BoolRef] | list[z3.ExprRef]) -> int:
        """Compute a structural hash of Z3 constraints using scoped id() cache.

        Uses id() for fast dict lookups, avoiding FFI overhead on cache hits.
        Cache is scoped to this instance's lifetime, preventing memory reuse bugs.

        Args:
            constraints: List of Z3 boolean constraints.

        Returns:
            Integer hash suitable for use as a cache key.
        """
        if not constraints:
            return 0

        hashes: list[int] = []
        for c in constraints:
            hashes.append(self.hash_expr(c))

        return hash(tuple(hashes))


def structural_hash(
    constraints: list[z3.BoolRef] | list[z3.ExprRef],
    hasher: ConstraintHasher | None = None,
) -> int:
    """Compute a structural hash of Z3 constraints using scoped id() cache.

    Args:
        constraints: List of Z3 boolean constraints.
        hasher: Optional ConstraintHasher instance. If None, creates a temporary
            instance (slower, but safe for one-off calls).

    Returns:
        Integer hash suitable for use as a cache key.
    """
    if hasher is None:
        temp_hasher = ConstraintHasher()
        return temp_hasher.structural_hash(constraints)
    return hasher.structural_hash(constraints)


_QUICK_CONTRADICTION_CACHE_MAX_SIZE = 4096
_QUICK_CONTRADICTION_HASHER = ConstraintHasher(max_cache_size=250_000)
_QUICK_CONTRADICTION_CACHE: OrderedDict[int, list[tuple[tuple[z3.BoolRef, ...], bool]]] = (
    OrderedDict()
)


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


@requires("cache_key == cache_key")
@requires("len(constraints) >= 0")
def _lookup_quick_contradiction_cache(cache_key: int, constraints: list[z3.BoolRef]) -> bool | None:
    bucket = _QUICK_CONTRADICTION_CACHE.get(cache_key)
    if bucket is None:
        return None
    _QUICK_CONTRADICTION_CACHE.move_to_end(cache_key)
    for cached_constraints, cached_result in bucket:
        if _same_constraint_sequence(cached_constraints, constraints):
            return cached_result
    return None


def _store_quick_contradiction_cache(
    cache_key: int, constraints: list[z3.BoolRef], result: bool
) -> None:
    entry = (tuple(constraints), result)
    bucket = _QUICK_CONTRADICTION_CACHE.get(cache_key)
    if bucket is None:
        _QUICK_CONTRADICTION_CACHE[cache_key] = [entry]
    else:
        bucket.append(entry)
        _QUICK_CONTRADICTION_CACHE.move_to_end(cache_key)
    while len(_QUICK_CONTRADICTION_CACHE) > _QUICK_CONTRADICTION_CACHE_MAX_SIZE:
        _QUICK_CONTRADICTION_CACHE.popitem(last=False)


@requires("len(constraints) >= 0")
def structural_hash_sorted(constraints: list[z3.BoolRef] | list[z3.ExprRef]) -> int:
    """Compute an order-independent structural hash of Z3 constraints.

    Sorts constraint hashes before combining so that the same set of
    constraints in any order produces the same hash.

    Args:
        constraints: List of Z3 boolean constraints.

    Returns:
        Integer hash independent of constraint ordering.
    """
    if not constraints:
        return 0
    hashes: list[int] = sorted([c.hash() for c in constraints])
    return hash(tuple(hashes))


@requires("len(constraints) >= 0")
def structural_digest(constraints: list[z3.BoolRef] | list[z3.ExprRef]) -> int:
    """Collision-resistant digest for correctness-critical cache keys.

    Uses structural hashing instead of slow string conversion.
    """
    if not constraints:
        return 0
    digest_hashes: list[int] = [c.hash() for c in constraints]
    return hash(tuple(digest_hashes))


@requires("expr == expr")
def simplify_expr(expr: z3.ExprRef) -> z3.ExprRef:
    """Simplify one Z3 expression through the constraint simplification SSoT."""
    return z3.simplify(expr)


@requires("expr == expr")
def simplify_bool_expr(expr: z3.BoolRef) -> z3.BoolRef:
    """Simplify one Boolean Z3 expression and preserve the BoolRef contract."""
    simplified = simplify_expr(expr)
    if not isinstance(simplified, z3.BoolRef):
        raise TypeError("simplified Boolean expression did not produce a BoolRef")
    return simplified


@requires("len(constraints) >= 0")
def simplify_constraints(constraints: list[z3.BoolRef]) -> list[z3.BoolRef]:
    """Simplify a list of Z3 constraints.

    For small sets, applies z3.simplify per constraint.
    For larger sets (>50), uses Z3 tactic pipeline for deeper simplification.

    Args:
        constraints: List of Z3 boolean constraints.

    Returns:
        Simplified list of constraints (possibly shorter).
    """
    if not constraints:
        return []

    filtered: list[z3.BoolRef] = []
    for c in constraints:
        if z3.is_true(c):
            continue
        if z3.is_false(c):
            return [z3.BoolVal(False)]
        simplified = simplify_bool_expr(c)
        if z3.is_true(simplified):
            continue
        if z3.is_false(simplified):
            return [z3.BoolVal(False)]
        filtered.append(simplified)

    if not filtered:
        return []

    if len(filtered) <= 50:
        return filtered

    return _tactic_simplify(filtered)


@requires("len(constraints) >= 0")
def _tactic_simplify(constraints: list[z3.BoolRef]) -> list[z3.BoolRef]:
    """Use Z3 tactics for deeper simplification of large constraint sets.

    Applies: simplify → propagate-values → ctx-solver-simplify with 200ms timeout.

    Args:
        constraints: List of Z3 boolean constraints.

    Returns:
        Simplified constraints, or original if tactic fails or times out.
    """
    try:
        goal = z3.Goal()
        goal.add(*constraints)
        tactic = z3.TryFor(z3.Then("simplify", "propagate-values", "ctx-solver-simplify"), 200)
        result = tactic(goal)
        if len(result) == 1:
            subgoal = result[0]
            simplified = list(subgoal)
            if simplified:
                return simplified

            return []

        return constraints
    except z3.Z3Exception:
        return constraints


@requires("expr == expr")
def _z3_decl_kind(expr: z3.ExprRef) -> int | None:
    """Return a Z3 declaration kind for application expressions."""
    try:
        return expr.decl().kind()
    except (AttributeError, z3.Z3Exception):
        return None


@requires("len(constraints) >= 0")
def quick_contradiction_check(constraints: list[z3.BoolRef]) -> bool:
    """Fast check for obvious contradictions without invoking the solver.

    Looks for explicit False values and direct negation pairs.
    Avoids calling z3.simplify() to keep this check truly cheap.

    Uses a two-level approach to prevent false positives from hash collisions:
    1. Check for explicit ``False`` literals (O(n)).
    2. For each constraint ``c``, check whether ``Not(c)`` is structurally
       present in the list using Z3's ``ExprRef.eq()`` (structural equality),
       falling back to the hash only as a pre-filter.

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

    cache_key = structural_hash(constraints, _QUICK_CONTRADICTION_HASHER)
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
                    _store_quick_contradiction_cache(cache_key, constraints, True)
                    return True

    _store_quick_contradiction_cache(cache_key, constraints, False)
    return False


@requires("len(constraints) >= 0")
def remove_subsumed(constraints: list[z3.BoolRef]) -> list[z3.BoolRef]:
    """Remove structurally duplicate constraints.

    Uses Z3 structural equality to detect and remove exact duplicates.
    Does not perform logical subsumption checking.

    Args:
        constraints: List of Z3 boolean constraints.

    Returns:
        Deduplicated list with structural duplicates removed.
    """
    if len(constraints) <= 1:
        return constraints

    seen: dict[int, list[z3.BoolRef]] = {}
    result: list[z3.BoolRef] = []
    for c in constraints:
        h = c.hash()
        bucket = seen.get(h)
        if bucket is None:
            seen[h] = [c]
            result.append(c)
            continue
        is_dup = False
        for existing in bucket:
            if c is existing or safe_z3_eq(c, existing):
                is_dup = True
                break
        if is_dup:
            continue
        bucket.append(c)
        result.append(c)

    return result
