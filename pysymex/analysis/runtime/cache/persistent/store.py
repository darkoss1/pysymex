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

"""SQLite-backed persistent cache with BLAKE2b-signed, pickled storage."""

from __future__ import annotations

import json
import pickle
import sqlite3
import time

from pysymex.analysis.runtime.cache.keying import CacheKey, CacheKeyType
from pysymex.analysis.runtime.cache.persistent.maintenance import PersistentCacheMaintenance
from pysymex.logger import get_logger
from pysymex.utils.hashing import stable_digest_hex

logger = get_logger(__name__)


class PersistentCache(PersistentCacheMaintenance):
    """SQLite-backed persistent cache with BLAKE2b integrity and pickle serialisation.

    All stored values are pickled, MAC-signed before writing, and
    verified on read.  Corrupt or tampered entries are silently removed.
    """

    def _delete_corrupt_entry_locked(self, key_str: str, conn: sqlite3.Connection) -> None:
        """Remove an unreadable cache row while the cache lock is held."""
        self._pending_access_updates.pop(key_str, None)
        conn.execute("DELETE FROM cache WHERE key = ?", (key_str,))
        conn.commit()

    def get(self, key: CacheKey) -> object | None:
        """Return the cached value for *key*, or ``None`` on miss."""
        found, value = self.lookup(key)
        if found:
            return value
        return None

    def lookup(self, key: CacheKey) -> tuple[bool, object | None]:
        """Return ``(True, value)`` on hit or ``(False, None)`` on miss.

        Verifies the BLAKE2b tag before unpickling.  Removes entries that
        fail MAC verification or unpickling.
        """
        key_str = key.to_string()
        with self.lock:
            conn = self._get_connection()
            cursor = conn.execute("SELECT * FROM cache WHERE key = ?", (key_str,))
            row = cursor.fetchone()
            if not row:
                return False, None

            if key_str not in self._pending_access_updates:
                self._pending_access_updates[key_str] = (time.time(), 1)
            else:
                _, count = self._pending_access_updates[key_str]
                self._pending_access_updates[key_str] = (time.time(), count + 1)

            if len(self._pending_access_updates) >= 100:
                self._flush_access_updates_locked()

            try:
                raw_blob = self._integrity.verify_and_extract(key_str, row["value_blob"])
                if raw_blob is None:
                    logger.warning(
                        "Cache MAC verification failed for cache key %s - removing entry",
                        key_str,
                    )
                    self._delete_corrupt_entry_locked(key_str, conn)
                    return False, None
                return True, pickle.loads(raw_blob)
            except (pickle.UnpicklingError, ValueError, TypeError, EOFError):
                logger.debug(
                    "Failed to deserialize cache entry %s - removing entry",
                    key_str,
                    exc_info=True,
                )
                self._delete_corrupt_entry_locked(key_str, conn)
                return False, None

    def put(
        self,
        key: CacheKey,
        value: object,
        dependencies: list[CacheKey] | None = None,
    ) -> bool:
        """Pickle, MAC-sign, and store *value* under *key*.  Returns ``True`` on success.

        Optional *dependencies* are recorded in the ``cache_deps`` table
        for recursive invalidation via ``invalidate_dependencies``.
        """
        key_str = key.to_string()
        try:
            raw_blob = pickle.dumps(value)
            signed_blob = self._integrity.sign(key_str, raw_blob)
            value_hash = stable_digest_hex(raw_blob)
            dep_list = dependencies or []
            dep_json = json.dumps([d.to_string() for d in dep_list])
            now = time.time()
            with self.lock:
                self._flush_access_updates_locked()
                conn = self._get_connection()
                conn.execute(
                    """
                    INSERT OR REPLACE INTO cache
                    (key, key_type, value_hash, value_blob, created_at,
                     accessed_at, access_count, dependencies)
                    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                    """,
                    (key_str, key.key_type.name, value_hash, signed_blob, now, now, dep_json),
                )
                conn.execute("DELETE FROM cache_deps WHERE cache_key = ?", (key_str,))
                if dep_list:
                    conn.executemany(
                        "INSERT OR IGNORE INTO cache_deps (cache_key, dependency) VALUES (?, ?)",
                        [(key_str, d.to_string()) for d in dep_list],
                    )
                conn.commit()
            return True
        except (pickle.PicklingError, TypeError, OSError):
            logger.debug("Failed to cache entry %s", key_str, exc_info=True)
            return False

    def remove(self, key: CacheKey) -> bool:
        """Delete the entry for *key*.  Returns ``True`` if a row was removed."""
        key_str = key.to_string()
        with self.lock:
            self._flush_access_updates_locked()
            conn = self._get_connection()
            cursor = conn.execute("DELETE FROM cache WHERE key = ?", (key_str,))
            conn.commit()
            return cursor.rowcount > 0

    def invalidate_by_type(self, key_type: CacheKeyType) -> int:
        """Delete all entries of a given ``CacheKeyType``.  Returns the number of rows removed."""
        with self.lock:
            self._flush_access_updates_locked()
            conn = self._get_connection()
            cursor = conn.execute("DELETE FROM cache WHERE key_type = ?", (key_type.name,))
            conn.commit()
            return cursor.rowcount

    def invalidate_dependencies(self, key: CacheKey) -> set[str]:
        """Recursively delete all entries that (transitively) depend on *key*.

        Uses a recursive CTE in SQLite to follow the ``cache_deps``
        graph.  Returns the set of invalidated key strings.
        """
        key_str = key.to_string()
        with self.lock:
            self._flush_access_updates_locked()
            conn = self._get_connection()
            cursor = conn.execute(
                """
                DELETE FROM cache WHERE key IN (
                    WITH RECURSIVE transitive_deps(cache_key) AS (
                        SELECT cache_key FROM cache_deps WHERE dependency = ?
                        UNION
                        SELECT d.cache_key FROM cache_deps d
                        JOIN transitive_deps t ON d.dependency = t.cache_key
                    )
                    SELECT cache_key FROM transitive_deps
                )
                RETURNING key
                """,
                (key_str,),
            )
            invalidated = {row["key"] for row in cursor}
            conn.commit()
        return invalidated


__all__ = ["PersistentCache"]
