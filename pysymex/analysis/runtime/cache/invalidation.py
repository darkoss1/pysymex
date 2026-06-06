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

"""Cache invalidation strategies, rules, and file-based caching.

Provides ``SmartInvalidator`` (rule-driven invalidation with immediate,
lazy, time-based, and dependency strategies) and ``FileCache`` (content-
hash-based caching that re-analyses only when a file changes).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path

from pysymex.analysis.runtime.cache.keying import CacheKey, CacheKeyType, hash_file
from pysymex.analysis.runtime.cache.tiered import TieredCache
from pysymex.logger import get_logger

logger = get_logger(__name__)


class InvalidationStrategy(Enum):
    """Enumeration of cache invalidation policies."""

    IMMEDIATE = auto()
    LAZY = auto()
    TIME_BASED = auto()
    DEPENDENCY = auto()


@dataclass
class InvalidationRule:
    """A single invalidation rule binding a key pattern to a strategy."""

    key_pattern: str
    strategy: InvalidationStrategy
    max_age_seconds: float | None = None
    dependencies: list[str] = field(default_factory=lambda: [])


class SmartInvalidator:
    """Rule-driven cache invalidator with dependency and staleness tracking.

    Applies ``fnmatch`` patterns to cache keys and executes the
    corresponding invalidation strategy (IMMEDIATE removal,
    LAZY marking, TIME_BASED expiry, or DEPENDENCY cascade).
    """

    def __init__(self, cache: TieredCache) -> None:
        """Initialize a SmartInvalidator instance with dependency tracking.

        Args:
            cache (TieredCache): The composable TieredCache composition.
        """
        self.cache = cache
        self.rules: list[InvalidationRule] = []
        self._stale: set[str] = set()
        self._timestamps: dict[str, float] = {}

    def add_rule(self, rule: InvalidationRule) -> None:
        """Register a new invalidation rule."""
        self.rules.append(rule)

    def on_change(self, key: CacheKey) -> set[str]:
        """Process a change to *key*, applying matching rules and returning invalidated key strings."""
        key_str = key.to_string()
        invalidated: set[str] = set()
        for rule in self.rules:
            if self._matches_pattern(key_str, rule.key_pattern):
                if rule.strategy == InvalidationStrategy.IMMEDIATE:
                    self.cache.remove(key)
                    deps = self.cache.persistent.invalidate_dependencies(key)
                    for dep_str in deps:
                        self.cache.memory.remove(dep_str)
                    invalidated.update(deps)
                    invalidated.add(key_str)
                elif rule.strategy == InvalidationStrategy.LAZY:
                    self._stale.add(key_str)
                elif rule.strategy == InvalidationStrategy.DEPENDENCY:
                    self.cache.remove(key)
                    deps = self.cache.persistent.invalidate_dependencies(key)
                    for dep_str in deps:
                        self.cache.memory.remove(dep_str)
                    invalidated.update(deps)
                    invalidated.add(key_str)
        return invalidated

    def is_stale(self, key: CacheKey) -> bool:
        """Return ``True`` if *key* has been lazily marked stale or has exceeded its time limit."""
        key_str = key.to_string()
        if key_str in self._stale:
            return True
        for rule in self.rules:
            if (
                rule.strategy == InvalidationStrategy.TIME_BASED
                and rule.max_age_seconds is not None
                and self._matches_pattern(key_str, rule.key_pattern)
            ):
                created = self._timestamps.get(key_str)
                if created is not None and time.time() - created > rule.max_age_seconds:
                    return True
        return False

    def mark_fresh(self, key: CacheKey) -> None:
        """Remove *key* from the stale set and update its freshness timestamp."""
        key_str = key.to_string()
        self._stale.discard(key_str)
        self._timestamps[key_str] = time.time()

    def _matches_pattern(self, key: str, pattern: str) -> bool:
        """Return whether *key* matches *pattern* using ``fnmatch`` semantics."""
        import fnmatch

        return fnmatch.fnmatch(key, pattern)


class FileCache:
    """Content-hash-based file analysis cache.

    Tracks stable file content hashes so that ``get_or_analyze`` skips
    re-analysis when file content is unchanged.  Backed by a
    ``TieredCache``.
    """

    def __init__(self, cache: TieredCache | None = None) -> None:
        """Initialize a FileCache instance to cache file-based analysis.

        Args:
            cache (TieredCache | None): Optional tiered cache layer. Defaults to a new TieredCache.
        """
        self.cache = cache or TieredCache()
        self._file_hashes: dict[str, str] = {}

    def close(self) -> None:
        """Close underlying cache resources."""
        self.cache.close()

    def __del__(self) -> None:
        """Best-effort close for test runs that create short-lived caches."""
        try:
            self.close()
        except Exception:
            logger.debug("File cache finalizer failed", exc_info=True)

    def get_or_analyze(
        self,
        path: Path,
        analyze_fn: Callable[[Path], object],
    ) -> tuple[object, bool]:
        """Return ``(result, True)`` if cached, or ``(analyze_fn(path), False)`` on miss.

        The cache key includes the file's current content hash, so a
        changed file always triggers re-analysis.
        """
        path_str = str(path.absolute())
        current_hash = hash_file(path)
        key = CacheKey(CacheKeyType.MODULE, path_str, version=current_hash)
        found, cached = self.cache.lookup(key)
        if found:
            self._file_hashes[path_str] = current_hash
            return cached, True
        result = analyze_fn(path)
        self._file_hashes[path_str] = current_hash
        self.cache.put(key, result)
        return result, False

    def invalidate(self, path: Path) -> None:
        """Remove the cached result for *path* (uses the last-known hash)."""
        path_str = str(path.absolute())
        cached_hash = self._file_hashes.pop(path_str, None)
        if cached_hash:
            key = CacheKey(CacheKeyType.MODULE, path_str, version=cached_hash)
            self.cache.remove(key)
        else:
            if not path.exists():
                return
            current_hash = hash_file(path)
            key = CacheKey(CacheKeyType.MODULE, path_str, version=current_hash)
            self.cache.remove(key)
