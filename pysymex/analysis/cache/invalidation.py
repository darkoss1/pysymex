"""Cache invalidation: strategies, rules, smart invalidation,
and file-based caching with hash tracking.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any

from pysymex.analysis.cache.core import (
    CacheKey,
    CacheKeyType,
    TieredCache,
    hash_file,
)


class InvalidationStrategy(Enum):
    """Cache invalidation strategies."""

    IMMEDIATE = auto()
    LAZY = auto()
    TIME_BASED = auto()
    DEPENDENCY = auto()


@dataclass
class InvalidationRule:
    """Rule for cache invalidation."""

    key_pattern: str
    strategy: InvalidationStrategy
    max_age_seconds: float | None = None
    dependencies: list[str] = field(default_factory=lambda: [])


class SmartInvalidator:
    """Manages smart cache invalidation.
    Tracks dependencies and applies invalidation rules
    to minimize unnecessary re-analysis.
    """

    def __init__(self, cache: TieredCache):
        self.cache = cache
        self.rules: list[InvalidationRule] = []
        self._stale: set[str] = set()
        self._timestamps: dict[str, float] = {}

    def add_rule(self, rule: InvalidationRule) -> None:
        """Add an invalidation rule."""
        self.rules.append(rule)

    def on_change(self, key: CacheKey) -> set[str]:
        """Handle a change event."""
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
                    deps = self.cache.persistent.invalidate_dependencies(key)
                    for dep_str in deps:
                        self.cache.memory.remove(dep_str)
                    invalidated.update(deps)
        return invalidated

    def is_stale(self, key: CacheKey) -> bool:
        """Check if a key is stale."""
        key_str = key.to_string()
        if key_str in self._stale:
            return True
        for rule in self.rules:
            if (
                rule.strategy == InvalidationStrategy.TIME_BASED
                and rule.max_age_seconds
                and self._matches_pattern(key_str, rule.key_pattern)
            ):
                created = self._timestamps.get(key_str)
                if created is not None and time.time() - created > rule.max_age_seconds:
                    return True
        return False

    def mark_fresh(self, key: CacheKey) -> None:
        """Mark a key as fresh."""
        key_str = key.to_string()
        self._stale.discard(key_str)
        self._timestamps[key_str] = time.time()

    def _matches_pattern(self, key: str, pattern: str) -> bool:
        """Check if key matches pattern."""
        import fnmatch

        return fnmatch.fnmatch(key, pattern)


class FileCache:
    """Cache for file-based analysis results.
    Tracks file hashes and only re-analyzes when content changes.
    """

    def __init__(self, cache: TieredCache | None = None):
        self.cache = cache or TieredCache()
        self._file_hashes: dict[str, str] = {}

    def get_or_analyze(
        self,
        path: Path,
        analyze_fn: Callable[[Path], Any],
    ) -> tuple[object, bool]:
        """Get cached result or run analysis.
        Returns (result, was_cached).
        """
        path_str = str(path.absolute())
        current_hash = hash_file(path)
        cached_hash = self._file_hashes.get(path_str)
        if cached_hash == current_hash:
            key = CacheKey(CacheKeyType.MODULE, path_str)
            cached = self.cache.get(key)
            if cached is not None:
                return cached, True
        result = analyze_fn(path)
        self._file_hashes[path_str] = current_hash
        key = CacheKey(CacheKeyType.MODULE, path_str)
        self.cache.put(key, result)
        return result, False

    def invalidate(self, path: Path) -> None:
        """Invalidate cache for a file."""
        path_str = str(path.absolute())
        self._file_hashes.pop(path_str, None)
        key = CacheKey(CacheKeyType.MODULE, path_str)
        self.cache.remove(key)
