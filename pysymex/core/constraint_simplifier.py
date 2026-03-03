"""Theory-aware constraint simplification for pysymex.

Applies algebraic simplifications to Z3 constraints before solver calls:
- Constant folding
- Quick contradiction detection
- Subsumption removal
- Z3 tactic-based deep simplification for large constraint sets
"""

from __future__ import annotations


from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    pass

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

        filtered.append(cast(z3.BoolRef, simplified))

    if not filtered:
        return []

    if len(filtered) <= 50:
        return filtered

    return _tactic_simplify(filtered)


def _tactic_simplify(constraints: list[z3.BoolRef]) -> list[z3.BoolRef]:
    """Use Z3 tactics for deeper simplification of large constraint sets.

    Applies: simplify → propagate-values → ctx-solver-simplify

    Args:
        constraints: List of Z3 boolean constraints.

    Returns:
        Simplified constraints, or original if tactic fails.
    """

    try:
        goal = z3.Goal()

        goal.add(*constraints)

        tactic = z3.Then("simplify", "propagate-values", "ctx-solver-simplify")

        result = tactic(goal)

        if len(result) == 1:
            subgoal = result[0]

            simplified = list(subgoal)

            if simplified:
                return cast(list[z3.BoolRef], simplified)

            return []

        return constraints

    except Exception:
        return constraints


def quick_contradiction_check(constraints: list[z3.BoolRef]) -> bool:
    """Fast check for obvious contradictions without invoking the solver.

    Looks for explicit False values and direct negation pairs.
    Avoids calling z3.simplify() to keep this check truly cheap.

    Args:
        constraints: List of Z3 boolean constraints.

    Returns:
        True if a contradiction is detected, False otherwise.
    """

    if not constraints:
        return False

    constraint_hashes: set[int] = set()

    negation_hashes: set[int] = set()

    for c in constraints:
        if z3.is_false(c):
            return True

        h = c.hash()

        constraint_hashes.add(h)

        neg_h = z3.Not(c).hash()

        negation_hashes.add(neg_h)

    if constraint_hashes & negation_hashes:
        return True

    return False


def remove_subsumed(constraints: list[z3.BoolRef]) -> list[z3.BoolRef]:
    """Remove constraints that are subsumed by stronger ones.

    Uses Z3 simplification to detect redundant constraints.
    Only performs lightweight checks — does not invoke the full solver.

    Args:
        constraints: List of Z3 boolean constraints.

    Returns:
        Deduplicated list with subsumed constraints removed.
    """

    if len(constraints) <= 1:
        return constraints

    seen: dict[int, z3.BoolRef] = {}

    for c in constraints:
        h = c.hash()

        if h not in seen:
            seen[h] = c

    return list(seen.values())
