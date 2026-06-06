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

"""Thread-safe in-memory LRU cache backed by ``OrderedDict``."""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Generic, TypeVar

from pysymex.analysis.runtime.cache.keying import cache_hit_rate

K = TypeVar("K")
V = TypeVar("V")


class LRUCache(Generic[K, V]):
    """Thread-safe LRU cache with a configurable size limit.

    Backed by an ``OrderedDict``; evicts the least-recently-used entry
    when ``maxsize`` is exceeded on ``put``.  All public methods acquire
    an ``RLock``.  Supports pickling (the lock is stripped and restored).
    """

    def __init__(self, maxsize: int = 1000) -> None:
        """Initialize a thread-safe LRU cache with a maximum capacity.

        Args:
            maxsize (int): The maximum number of entries to retain. Defaults to 1000.
        """
        if maxsize < 0:
            raise ValueError("LRU cache maxsize must be non-negative")
        self.maxsize = maxsize
        self.cache: OrderedDict[K, V] = OrderedDict()
        self.lock = threading.RLock()
        self.hits = 0
        self.misses = 0

    def get(self, key: K, default: V | None = None) -> V | None:
        """Return the cached value for *key*, or *default* on miss."""
        found, value = self.lookup(key)
        if found:
            return value
        return default

    def lookup(self, key: K) -> tuple[bool, V | None]:
        """Return ``(True, value)`` on hit or ``(False, None)`` on miss.

        Moves a hit entry to the end (most-recently-used position).
        Updates hit/miss counters.
        """
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
                self.hits += 1
                return True, self.cache[key]
            self.misses += 1
            return False, None

    def put(self, key: K, value: V) -> None:
        """Insert or update *key*.  Evicts the oldest entry when over capacity."""
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            self.cache[key] = value
            while len(self.cache) > self.maxsize:
                self.cache.popitem(last=False)

    def remove(self, key: K) -> bool:
        """Remove *key* if present.  Returns ``True`` if the key was found."""
        with self.lock:
            if key in self.cache:
                del self.cache[key]
                return True
            return False

    def clear(self) -> None:
        """Remove all entries and reset hit/miss counters."""
        with self.lock:
            self.cache.clear()
            self.hits = 0
            self.misses = 0

    def __contains__(self, key: K) -> bool:
        """Return whether *key* is in the cache (does not count as a hit)."""
        with self.lock:
            return key in self.cache

    def __len__(self) -> int:
        """Return the number of elements in the container."""
        with self.lock:
            return len(self.cache)

    @property
    def hit_rate(self) -> float:
        """Return the cache hit ratio (0.0 – 1.0)."""
        return cache_hit_rate(self.hits, self.misses)

    def __getstate__(self) -> dict[str, object]:
        """Prepare the cache instance dictionary state for serialization (pickling).

        Strips the active thread lock to prevent serialization errors.

        Returns:
            dict[str, object]: Serialized instance dictionary state.
        """
        state = self.__dict__.copy()
        state["lock"] = None
        return state

    def __setstate__(self, state: dict[str, object]) -> None:
        """Reconstruct the cache instance dictionary state after deserialization (unpickling).

        Re-initializes a fresh reentrant lock thread helper.

        Args:
            state (dict[str, object]): Pickled state dictionary.
        """
        self.__dict__.update(state)
        self.lock = threading.RLock()

    def stats(self) -> dict[str, object]:
        """Return a dict with size, maxsize, hits, misses, and hit_rate."""
        with self.lock:
            return {
                "size": len(self.cache),
                "maxsize": self.maxsize,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": self.hit_rate,
            }


__all__ = ["LRUCache"]
