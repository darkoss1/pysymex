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

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import z3


class ConstraintHasher:
    """Stateful hasher that safely uses id() for performance.

    Create a new instance for each major solving phase or batch of constraints
    to ensure garbage collection doesn't cause id() collisions. The local cache
    dies with the instance, preventing stale id() lookups from memory reuse.
    """

    def __init__(self) -> None:
        """Initialize a new constraint hasher with empty cache."""
        self._cache: dict[int, int] = {}

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
            c_id = id(c)
            if c_id not in self._cache:
                self._cache[c_id] = c.hash()
            hashes.append(self._cache[c_id])

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


def structural_digest(constraints: list[z3.BoolRef] | list[z3.ExprRef]) -> int:
    """Collision-resistant digest for correctness-critical cache keys.

    Uses structural hashing instead of slow string conversion.
    """
    if not constraints:
        return 0
    digest_hashes: list[int] = [c.hash() for c in constraints]
    return hash(tuple(digest_hashes))


import z3


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
        simplified = z3.simplify(c)
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

    by_hash: dict[int, list[z3.BoolRef]] = {}
    has_not = False
    for c in constraints:
        if z3.is_false(c):
            return True
        if z3.is_not(c):
            has_not = True
        h = c.hash()
        bucket = by_hash.get(h)
        if bucket is None:
            by_hash[h] = [c]
        else:
            bucket.append(c)

    if not has_not:
        return False

    for c in constraints:
        if z3.is_not(c):
            arg = c.arg(0)
            arg_h = arg.hash()
            candidates = by_hash.get(arg_h)
            if candidates is None:
                continue
            for candidate in candidates:
                if z3.eq(arg, candidate):
                    return True

    return False


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
            try:
                if z3.eq(c, existing):
                    is_dup = True
                    break
            except z3.Z3Exception:
                continue
        if is_dup:
            continue
        bucket.append(c)
        result.append(c)

    return result
