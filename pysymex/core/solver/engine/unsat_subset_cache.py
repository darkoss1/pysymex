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

"""Pure helper functions for exact UNSAT-subset cache validation."""

from __future__ import annotations

import z3

from pysymex.core.z3_utils import safe_z3_eq

__all__ = [
    "constraint_hash_counts",
    "constraint_hash_counts_contained",
    "constraint_hash_counts_from_buckets",
    "unsat_subset_matches",
]


def constraint_hash_counts(hashes: tuple[int, ...]) -> tuple[tuple[int, int], ...]:
    """Return deterministic hash multiplicities for a constraint collection."""
    counts: dict[int, int] = {}
    for constraint_hash in hashes:
        counts[constraint_hash] = counts.get(constraint_hash, 0) + 1
    return tuple(sorted(counts.items()))


def constraint_hash_counts_from_buckets(
    buckets: dict[int, list[z3.BoolRef]],
) -> dict[int, int]:
    """Return query hash multiplicities from already-built hash buckets."""
    return {constraint_hash: len(bucket) for constraint_hash, bucket in buckets.items()}


def constraint_hash_counts_contained(
    *,
    subset_counts: tuple[tuple[int, int], ...],
    query_counts: dict[int, int],
) -> bool:
    """Return whether a query contains each subset hash with enough multiplicity."""
    for constraint_hash, subset_count in subset_counts:
        if query_counts.get(constraint_hash, 0) < subset_count:
            return False
    return True


def unsat_subset_matches(
    subset: tuple[z3.BoolRef, ...],
    subset_hashes: tuple[int, ...],
    query_buckets: dict[int, list[z3.BoolRef]],
) -> bool:
    """Return whether every cached UNSAT constraint appears in a query."""
    used_by_hash: dict[int, set[int]] = {}
    for subset_constraint, constraint_hash in zip(subset, subset_hashes, strict=True):
        candidates = query_buckets.get(constraint_hash)
        if candidates is None:
            return False
        used = used_by_hash.setdefault(constraint_hash, set())
        matched_index = _find_matching_constraint_index(subset_constraint, candidates, used)
        if matched_index is None:
            return False
        used.add(matched_index)
    return True


def _find_matching_constraint_index(
    expected: z3.BoolRef,
    candidates: list[z3.BoolRef],
    used: set[int],
) -> int | None:
    """Find an unused structurally identical candidate constraint."""
    for index, candidate in enumerate(candidates):
        if index in used:
            continue
        if expected is candidate or safe_z3_eq(expected, candidate):
            return index
    return None
