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

"""Two-level cache composing an in-memory LRU with SQLite-backed persistent storage."""

from __future__ import annotations

from pathlib import Path

from pysymex.analysis.runtime.cache.keying import CacheKey
from pysymex.analysis.runtime.cache.memory import LRUCache
from pysymex.analysis.runtime.cache.persistent.store import PersistentCache
from pysymex.logger import get_logger

logger = get_logger(__name__)


class TieredCache:
    """Two-level cache: fast in-memory LRU backed by persistent SQLite storage.

    Lookups check memory first, then persistent; hits are promoted to
    memory.  Writes go to both layers by default (controlled by the
    ``persist`` flag on ``put``).
    """

    def __init__(
        self,
        memory_size: int = 1000,
        db_path: Path | None = None,
    ) -> None:
        """Initialize a composite TieredCache combining LRU and persistent layers.

        Args:
            memory_size (int): Capacity limit of the in-memory LRU layer. Defaults to 1000.
            db_path (Path | None): Optional Path to the SQLite database.
        """
        self.memory = LRUCache[str, object](maxsize=memory_size)
        self.persistent = PersistentCache(db_path=db_path)

    def get(self, key: CacheKey) -> object | None:
        """Return the cached value for *key*, or ``None`` on miss."""
        found, value = self.lookup(key)
        if found:
            return value
        return None

    def lookup(self, key: CacheKey) -> tuple[bool, object | None]:
        """Return ``(True, value)`` on hit or ``(False, None)`` on miss.

        Memory is checked first; on a persistent hit the value is
        promoted to the memory tier.
        """
        key_str = key.to_string()
        found, value = self.memory.lookup(key_str)
        if found:
            return True, value
        found, value = self.persistent.lookup(key)
        if found:
            self.memory.put(key_str, value)
            return True, value
        return False, None

    def put(
        self,
        key: CacheKey,
        value: object,
        persist: bool = True,
        dependencies: list[CacheKey] | None = None,
    ) -> None:
        """Store *value* under *key*.  Writes to both tiers when *persist* is ``True``.

        Before persisting, existing dependency chains are invalidated
        and removed from the memory tier.
        """
        key_str = key.to_string()
        if persist:
            invalidated = self.persistent.invalidate_dependencies(key)
            for dependency in invalidated:
                self.memory.remove(dependency)
        self.memory.put(key_str, value)
        if persist:
            if not self.persistent.put(key, value, dependencies):
                removed = self.persistent.remove(key)
                if removed:
                    logger.debug(
                        "Removed stale persistent cache entry after failed write: %s",
                        key_str,
                    )

    def remove(self, key: CacheKey) -> bool:
        """Remove *key* from both tiers.  Returns ``True`` if found in either tier."""
        key_str = key.to_string()
        mem_removed = self.memory.remove(key_str)
        pers_removed = self.persistent.remove(key)
        return mem_removed or pers_removed

    def clear(self) -> None:
        """Clear all entries in both tiers."""
        self.memory.clear()
        self.persistent.clear()

    def close(self) -> None:
        """Close persistent resources held by this cache."""
        self.persistent.close()

    def __del__(self) -> None:
        """Best-effort close for deterministic cleanup in short-lived test objects."""
        try:
            self.close()
        except Exception:
            logger.debug("Tiered cache finalizer failed", exc_info=True)

    def stats(self) -> dict[str, object]:
        """Return combined memory and persistent statistics."""
        return {
            "memory": self.memory.stats(),
            "persistent": self.persistent.stats(),
        }


__all__ = ["TieredCache"]
