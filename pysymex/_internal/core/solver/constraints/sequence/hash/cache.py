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

"""Long constraint-sequence hash cache validation helpers."""

from __future__ import annotations

import weakref
from typing import Final

import z3

SEQUENCE_CACHE_MIN_LENGTH: Final = 64
SEQUENCE_CACHE_MAX_ENTRIES: Final = 4096

ConstraintSequence = list[z3.BoolRef] | list[z3.ExprRef]
SequenceHashCache = dict[
    tuple[int, ...],
    tuple[tuple[weakref.ReferenceType[z3.ExprRef], ...], int],
]


def sequence_hash_cache_max_size(max_cache_size: int) -> int:
    """Return the sequence-cache entry limit derived from the expression-cache limit."""
    return min(max_cache_size, SEQUENCE_CACHE_MAX_ENTRIES)


def lookup_sequence_hash(
    cache: SequenceHashCache,
    constraints: ConstraintSequence,
) -> int | None:
    """Return a cached sequence hash after validating every live wrapper."""
    constraint_count = len(constraints)
    if constraint_count < SEQUENCE_CACHE_MIN_LENGTH:
        return None

    key = tuple(id(c) for c in constraints)
    sequence_cached = cache.get(key)
    if sequence_cached is None:
        return None

    cached_refs, cached_hash = sequence_cached
    for cached_ref, constraint in zip(cached_refs, constraints, strict=True):
        if cached_ref() is not constraint:
            return None
    return cached_hash


def store_sequence_hash(
    cache: SequenceHashCache,
    constraints: ConstraintSequence,
    combined: int,
    *,
    max_cache_size: int,
) -> None:
    """Store a long sequence hash guarded by weakrefs to each expression wrapper."""
    if len(constraints) < SEQUENCE_CACHE_MIN_LENGTH:
        return

    if len(cache) >= max_cache_size:
        cache.clear()
    key = tuple(id(c) for c in constraints)
    cache[key] = (
        tuple(weakref.ref(constraint) for constraint in constraints),
        combined,
    )
