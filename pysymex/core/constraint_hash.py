"""Structural constraint hashing for pysymex.

Provides content-addressable hashing for Z3 constraints using native
AST-based hashing instead of expensive string conversion.
"""

from __future__ import annotations


from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import z3


def structural_hash(constraints: list[z3.BoolRef] | list[z3.ExprRef]) -> int:
    """Compute a structural hash of Z3 constraints using native AST hashing.

    Uses Z3's built-in __hash__ which is based on expression structure,
    avoiding the expensive str() conversion used previously.

    Args:
        constraints: List of Z3 boolean constraints.

    Returns:
        Integer hash suitable for use as a cache key.
    """

    h = 0

    for c in constraints:
        h ^= c.hash()

        h = (h * 2654435761) & 0xFFFFFFFF

    return h


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

    hashes = sorted(c.hash() for c in constraints)

    h = 0

    for ch in hashes:
        h ^= ch

        h = (h * 2654435761) & 0xFFFFFFFF

    return h
