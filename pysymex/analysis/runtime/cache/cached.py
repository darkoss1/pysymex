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

"""Decorator-style wrapper that adds caching to an analysis function."""

from __future__ import annotations

from collections.abc import Callable

from pysymex.analysis.runtime.cache.keying import CacheKey, cache_hit_rate
from pysymex.analysis.runtime.cache.tiered import TieredCache


class CachedAnalysis:
    """Wrapper that adds tiered (LRU + persistent) caching to an analysis callable.

    Tracks hit/miss counts.  The caller supplies the analysis function and a
    key-derivation function; this class handles lookup, storage, and stats.
    """

    def __init__(
        self,
        analyze_fn: Callable[[object], object],
        key_fn: Callable[[object], CacheKey],
        cache: TieredCache | None = None,
    ) -> None:
        """Initialize a CachedAnalysis wrapper around an analysis function.

        Args:
            analyze_fn (Callable[[object], object]): The function that executes the analysis.
            key_fn (Callable[[object], CacheKey]): Function mapping targets to unique cache keys.
            cache (TieredCache | None): Optional composable Cache instance to use. Defaults to a new TieredCache.
        """
        self.analyze_fn = analyze_fn
        self.key_fn = key_fn
        self.cache = cache or TieredCache()
        self.hits = 0
        self.misses = 0

    def __call__(self, target: object) -> object:
        """Run *target* through the cache, invoking ``analyze_fn`` on miss."""
        key = self.key_fn(target)
        found, cached = self.cache.lookup(key)
        if found:
            self.hits += 1
            return cached
        self.misses += 1
        result = self.analyze_fn(target)
        self.cache.put(key, result)
        return result

    def invalidate(self, target: object) -> None:
        """Remove the cached result for *target* from the tiered cache."""
        key = self.key_fn(target)
        self.cache.remove(key)

    @property
    def hit_rate(self) -> float:
        """Return cache hit ratio (0.0 – 1.0).  Returns 0.0 when no lookups have occurred."""
        return cache_hit_rate(self.hits, self.misses)

    def stats(self) -> dict[str, object]:
        """Return a dict with hits, misses, hit_rate, and underlying cache stats."""
        return {
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": self.hit_rate,
            "cache": self.cache.stats(),
        }


__all__ = ["CachedAnalysis"]
