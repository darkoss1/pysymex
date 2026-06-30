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

"""Structural hashing helpers for Z3 constraints."""

from __future__ import annotations

import weakref
from typing import TYPE_CHECKING

from pysymex._internal.core.cache.control import is_process_cache_disabled
from pysymex._internal.core.solver.constraints.attached.hashes import (
    Z3_HASH_ATTR as _Z3_HASH_ATTR,
)
from pysymex._internal.core.solver.constraints.attached.hashes import (
    attached_hash as _attached_hash,
)
from pysymex._internal.core.solver.constraints.attached.hashes import (
    combined_attached_hash,
    combined_attached_sorted_hash,
)
from pysymex._internal.core.solver.constraints.attached.hashes import (
    try_attach_hash as _try_attach_hash,
)
from pysymex._internal.core.solver.constraints.sequence.hash.cache import (
    SEQUENCE_CACHE_MAX_ENTRIES,
    SEQUENCE_CACHE_MIN_LENGTH,
    SequenceHashCache,
    lookup_sequence_hash,
    sequence_hash_cache_max_size,
    store_sequence_hash,
)
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    import z3

_SEQUENCE_CACHE_MIN_LENGTH = SEQUENCE_CACHE_MIN_LENGTH
_SEQUENCE_CACHE_MAX_ENTRIES = SEQUENCE_CACHE_MAX_ENTRIES
logger = get_logger(__name__)


def _compute_attached_hash(constraint: z3.ExprRef) -> int:
    """Compute and attach a Z3 structural hash for the common fast path."""
    computed = constraint.hash()
    _try_attach_hash(constraint, computed)
    return computed


def _combined_attached_hash(constraints: list[z3.BoolRef] | list[z3.ExprRef]) -> int:
    """Return an ordered tuple hash using expression-local hash caches."""
    return combined_attached_hash(constraints, compute_hash=_compute_attached_hash)


class ConstraintHasher:
    """Stateful Z3 structural-hash helper with a fallback weakref cache.

    Normal Z3 Python wrappers allow dynamic attributes, so the hot path stores
    each structural hash directly on the wrapper. The per-instance weakref cache
    is retained only for wrappers that cannot carry attributes, avoiding stale
    id reuse while keeping the common path allocation-light.

    Limitations:
        Hashes are prefilters only; callers making correctness decisions must
        validate candidate expressions after a matching hash.
    """

    def __init__(self, max_cache_size: int = 1_000_000) -> None:
        """Initialize a new constraint hasher with empty cache.

        Args:
            max_cache_size: Maximum number of cached expression ids before
                the cache is cleared to avoid long-lived stale-id reuse.

        """
        if max_cache_size <= 0:
            msg = "max_cache_size must be > 0"
            raise ValueError(msg)
        self.cache: dict[int, tuple[weakref.ReferenceType[z3.ExprRef], int]] = {}
        self._sequence_cache: SequenceHashCache = {}
        self._max_cache_size = max_cache_size
        self._max_sequence_cache_size = sequence_hash_cache_max_size(max_cache_size)

    def clear(self) -> None:
        """Clear the internal fallback caches.

        Expression-local attached hashes remain on their Z3 wrappers; this
        mirrors the previous behavior where ``clear`` did not remove attached
        ``_symex_hash`` attributes.
        """
        self.cache.clear()
        self._sequence_cache.clear()

    def cache_size(self) -> int:
        """Return the number of entries in the fallback weakref cache."""
        self._prune_dead_entries()
        return len(self.cache)

    def _prune_dead_entries(self) -> None:
        """Remove entries whose Z3 wrapper has been garbage-collected."""
        stale_ids: list[int] = [
            expr_id for expr_id, (expr_ref, _) in self.cache.items() if expr_ref() is None
        ]
        for expr_id in stale_ids:
            del self.cache[expr_id]

    def hash_expr(self, constraint: z3.ExprRef) -> int:
        """Return a cached Z3 structural hash for one expression."""
        if is_process_cache_disabled():
            return constraint.hash()

        attached = _attached_hash(constraint)
        if attached is not None:
            return attached

        constraint_id = id(constraint)
        cached = self.cache.get(constraint_id)
        if cached is not None:
            cached_expr, cached_hash = cached
            if cached_expr() is constraint:
                return cached_hash

        computed = constraint.hash()
        if _try_attach_hash(constraint, computed):
            return computed

        if len(self.cache) >= self._max_cache_size:
            self._prune_dead_entries()
        if len(self.cache) >= self._max_cache_size:
            logger.verbose("Clearing constraint hash fallback cache at size=%d", len(self.cache))
            self.cache.clear()
        self.cache[constraint_id] = (weakref.ref(constraint), computed)
        return computed

    def structural_hash(self, constraints: list[z3.BoolRef] | list[z3.ExprRef]) -> int:
        """Compute an ordered combined hash of Z3 expression structures.

        The hot path reads expression-local cached hashes directly and falls
        back to :meth:`hash_expr` only for uncached expressions. Repeated long
        lists also use a guarded sequence cache that validates every live
        expression object before returning a cached combined hash.

        Args:
            constraints: List of Z3 boolean constraints.

        Returns:
            Integer hash suitable as a prefilter component of a cache key.

        Limitations:
            Hash equality does not prove equality of constraint sequences.

        """
        if not constraints:
            return 0

        if is_process_cache_disabled():
            return hash(tuple(constraint.hash() for constraint in constraints))

        sequence_cached = lookup_sequence_hash(self._sequence_cache, constraints)
        if sequence_cached is not None:
            return sequence_cached

        hashes: list[int] = []
        append_hash = hashes.append
        hash_attr = _Z3_HASH_ATTR
        hash_uncached = self.hash_expr
        for c in constraints:
            cached: int | None = getattr(c, hash_attr, None)
            if cached is not None:
                append_hash(cached)
            else:
                append_hash(hash_uncached(c))

        combined = hash(tuple(hashes))
        store_sequence_hash(
            self._sequence_cache,
            constraints,
            combined,
            max_cache_size=self._max_sequence_cache_size,
        )
        return combined


def structural_hash(
    constraints: list[z3.BoolRef] | list[z3.ExprRef],
    hasher: ConstraintHasher | None = None,
) -> int:
    """Compute an ordered combined hash of Z3 expression structures.

    Args:
        constraints: List of Z3 boolean constraints.
        hasher: Optional :class:`ConstraintHasher` used to reuse live-wrapper
            hash computations.

    Returns:
        Integer hash suitable as a prefilter component of a cache key.

    Limitations:
        Hash equality does not prove equality of constraint sequences.

    """
    if is_process_cache_disabled():
        return hash(tuple(constraint.hash() for constraint in constraints))
    if hasher is None:
        return _combined_attached_hash(constraints)
    return hasher.structural_hash(constraints)


def structural_hash_sorted(constraints: list[z3.BoolRef] | list[z3.ExprRef]) -> int:
    """Compute an order-independent structural hash of Z3 constraints.

    Sorts constraint hashes before combining so that the same set of
    constraints in any order produces the same hash.

    Args:
        constraints: List of Z3 boolean constraints.

    Returns:
        Integer hash independent of constraint ordering.

    Limitations:
        Hash equality does not prove equality of unordered constraint sets.

    """
    if not constraints:
        return 0
    if is_process_cache_disabled():
        return hash(tuple(sorted(constraint.hash() for constraint in constraints)))
    return combined_attached_sorted_hash(constraints, compute_hash=_compute_attached_hash)
