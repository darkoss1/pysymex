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

"""Persistent cache maintenance and summary operations."""

from __future__ import annotations

import time

from pysymex.analysis.runtime.cache.keying import CacheKey
from pysymex.analysis.runtime.cache.persistent.base import PersistentCacheBase


class PersistentCacheMaintenance(PersistentCacheBase):
    """Maintenance, statistics, and cleanup operations for the SQLite cache.

    Extends ``PersistentCacheBase`` with age-based expiry, capacity-based
    eviction, and row-count/access statistics.
    """

    def clear(self) -> int:
        """Delete all cache entries and return the number of rows removed."""
        with self.lock:
            self._flush_access_updates_locked()
            conn = self._get_connection()
            cursor = conn.execute("DELETE FROM cache")
            conn.commit()
            return cursor.rowcount

    def cleanup(self) -> int:
        """Remove entries older than ``max_age_days`` and evict LRU entries beyond ``max_entries``.

        Returns:
            Total number of rows deleted.
        """
        removed = 0
        now = time.time()
        max_age_seconds = self.max_age_days * 24 * 60 * 60
        with self.lock:
            self._flush_access_updates_locked()
            conn = self._get_connection()
            cursor = conn.execute(
                "DELETE FROM cache WHERE created_at < ?", (now - max_age_seconds,)
            )
            removed += cursor.rowcount
            cursor = conn.execute("SELECT COUNT(*) FROM cache")
            count = cursor.fetchone()[0]
            if count > self.max_entries:
                excess = count - self.max_entries
                conn.execute(
                    """
                    DELETE FROM cache WHERE key IN (
                        SELECT key FROM cache
                        ORDER BY accessed_at ASC
                        LIMIT ?
                    )
                    """,
                    (excess,),
                )
                removed += excess
            conn.commit()
        return removed

    def stats(self) -> dict[str, object]:
        """Return a dict with db_path, entry_count, by_type breakdown, total_accesses, and max_entries."""
        with self.lock:
            self._flush_access_updates_locked()
            conn = self._get_connection()
            cursor = conn.execute("SELECT COUNT(*) FROM cache")
            count = cursor.fetchone()[0]
            cursor = conn.execute("SELECT key_type, COUNT(*) as cnt FROM cache GROUP BY key_type")
            by_type = {row["key_type"]: row["cnt"] for row in cursor}
            cursor = conn.execute("SELECT SUM(access_count) as total FROM cache")
            total_accesses = cursor.fetchone()["total"] or 0
            return {
                "db_path": str(self.db_path),
                "entry_count": count,
                "by_type": by_type,
                "total_accesses": total_accesses,
                "max_entries": self.max_entries,
            }

    def __contains__(self, key: CacheKey) -> bool:
        """Return ``True`` if *key* exists in the database."""
        key_str = key.to_string()
        with self.lock:
            conn = self._get_connection()
            cursor = conn.execute("SELECT 1 FROM cache WHERE key = ?", (key_str,))
            return cursor.fetchone() is not None

    def __len__(self) -> int:
        """Return the number of elements in the container."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.execute("SELECT COUNT(*) FROM cache")
            return cursor.fetchone()[0]


__all__ = ["PersistentCacheMaintenance"]
