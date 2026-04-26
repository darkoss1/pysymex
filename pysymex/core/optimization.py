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

"""Performance optimization utilities for pysymex.
This module provides:
- Constraint caching for faster satisfiability checks
- State merging to reduce path explosion
- Lazy symbolic value evaluation
- Memory-efficient state representation
"""

from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

import z3

from pysymex.core.solver.engine import create_solver

logger = logging.getLogger(__name__)


@dataclass
class CacheStats:
    """Statistics for constraint cache performance."""

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    total_time_saved_ms: float = 0.0

    @property
    def hit_rate(self) -> float:
        """Return cache hit rate as a percentage."""
        total = self.hits + self.misses
        return (self.hits / total * 100) if total > 0 else 0.0

    def __str__(self) -> str:
        """Return a human-readable string representation."""
        return (
            f"CacheStats(hits={self.hits}, misses={self.misses}, "
            f"hit_rate={self.hit_rate:.1f}%, time_saved={self.total_time_saved_ms:.1f}ms)"
        )


class ConstraintCache:
    """LRU cache for constraint satisfiability results.
    Caches the results of Z3 satisfiability checks to avoid
    redundant solver invocations. Uses constraint normalization
    and hashing for efficient lookup.
    """

    def __init__(self, max_size: int = 10000) -> None:
        self.max_size = max_size
        self._cache: OrderedDict[
            tuple[int, tuple[int, ...]], tuple[bool, z3.ModelRef | None, float]
        ] = OrderedDict()
        self._cache_index: dict[int, set[tuple[int, ...]]] = {}
        self.stats = CacheStats()

    def _hash_constraints(self, constraints: list[z3.ExprRef] | list[z3.BoolRef]) -> int:
        """Generate a hash for a list of constraints using structural hashing."""
        from pysymex.core.solver.constraints import structural_hash_sorted

        return structural_hash_sorted(constraints)

    @staticmethod
    def _constraints_discriminator(
        constraints: list[z3.ExprRef] | list[z3.BoolRef],
    ) -> tuple[int, ...]:
        """Secondary discriminator for cache collision detection."""
        if not constraints:
            return ()
        return tuple(sorted(c.hash() for c in constraints))

    def get(
        self,
        constraints: list[z3.ExprRef] | list[z3.BoolRef],
    ) -> tuple[bool, z3.ModelRef | None] | None:
        """Look up cached result for constraints."""
        key = self._hash_constraints(constraints)
        discriminator = self._constraints_discriminator(constraints)
        bucket = self._cache_index.get(key)
        if bucket is None:
            self.stats.misses += 1
            return None
        if discriminator not in bucket:
            logger.debug("SAT cache collision detected")
            self.stats.misses += 1
            return None
        cache_key = (key, discriminator)
        cached = self._cache.get(cache_key)
        if cached is None:
            self.stats.misses += 1
            return None
        self.stats.hits += 1
        sat, model, time_taken = cached
        self.stats.total_time_saved_ms += time_taken
        self._cache.move_to_end(cache_key)
        return (sat, model)

    def put(
        self,
        constraints: list[z3.ExprRef] | list[z3.BoolRef],
        satisfiable: bool,
        model: z3.ModelRef | None,
        time_taken_ms: float,
    ) -> None:
        """Store result in cache."""
        key = self._hash_constraints(constraints)
        discriminator = self._constraints_discriminator(constraints)
        cache_key = (key, discriminator)
        if cache_key in self._cache:
            self._cache[cache_key] = (satisfiable, model, time_taken_ms)
            self._cache.move_to_end(cache_key)
            self._cache_index.setdefault(key, set()).add(discriminator)
            return
        while len(self._cache) >= self.max_size:
            old_key, _ = self._cache.popitem(last=False)
            old_primary, old_discriminator = old_key
            bucket = self._cache_index.get(old_primary)
            if bucket is not None:
                bucket.discard(old_discriminator)
                if not bucket:
                    del self._cache_index[old_primary]
            self.stats.evictions += 1
        self._cache[cache_key] = (satisfiable, model, time_taken_ms)
        self._cache_index.setdefault(key, set()).add(discriminator)

    def clear(self) -> None:
        """Clear the cache."""
        self._cache.clear()
        self._cache_index.clear()

    def __len__(self) -> int:
        """Return the number of elements in the container."""
        return len(self._cache)


_global_cache: ConstraintCache | None = None
_global_cache_lock = threading.Lock()


def get_constraint_cache(max_size: int = 10000) -> ConstraintCache:
    """Get the global constraint cache, creating if needed.

    Thread-safe via double-checked locking.
    """
    global _global_cache
    if _global_cache is not None:
        return _global_cache
    with _global_cache_lock:
        if _global_cache is None:
            _global_cache = ConstraintCache(max_size)
        return _global_cache


def cached_is_satisfiable(
    constraints: list[z3.ExprRef] | list[z3.BoolRef],
    cache: ConstraintCache | None = None,
) -> bool:
    """Check satisfiability with caching."""
    if cache is None:
        cache = get_constraint_cache()
    cached_result = cache.get(constraints)
    if cached_result is not None:
        return cached_result[0]
    start_time = time.perf_counter()
    solver = create_solver()
    solver.add(constraints)
    result = solver.check() == z3.sat
    model = solver.model() if result else None
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    cache.put(constraints, result, model, elapsed_ms)
    return result


__all__ = [
    "CacheStats",
    "ConstraintCache",
    "cached_is_satisfiable",
    "get_constraint_cache",
]
