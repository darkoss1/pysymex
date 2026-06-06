"""Tests for SQLite-backed persistent cache."""

from __future__ import annotations

import pickle
import time
from pathlib import Path

from pysymex.analysis.runtime.cache.integrity import CacheIntegrity
from pysymex.analysis.runtime.cache.keying import CacheKey, CacheKeyType
from pysymex.analysis.runtime.cache.persistent.store import PersistentCache
from pysymex.analysis.runtime.cache.persistent.types import CacheEntry
from pysymex.utils.hashing import stable_digest_hex


class TestCacheEntry:
    """Test suite for pysymex.analysis.runtime.cache.persistent.types.CacheEntry."""

    def test_age(self) -> None:
        now = time.time()
        entry = CacheEntry("k", "t", "h", b"v", now - 10, now, 1, "[]")
        assert entry.age >= 10


class TestPersistentCache:
    """Test suite for pysymex.analysis.runtime.cache.persistent.store.PersistentCache."""

    def test_close(self, tmp_path: Path) -> None:
        cache = PersistentCache(db_path=tmp_path / "cache.db")
        cache.close()
        assert cache.conn is None

    def test_get(self, tmp_path: Path) -> None:
        cache = PersistentCache(db_path=tmp_path / "cache.db")
        key = CacheKey(CacheKeyType.FUNCTION, "f1")
        assert cache.get(key) is None
        cache.put(key, {"data": 42})
        assert cache.get(key) == {"data": 42}
        cache.close()

    def test_lookup_distinguishes_cached_none_from_miss(self, tmp_path: Path) -> None:
        cache = PersistentCache(db_path=tmp_path / "cache.db")
        key = CacheKey(CacheKeyType.FUNCTION, "f1")
        missing = CacheKey(CacheKeyType.FUNCTION, "missing")

        cache.put(key, None)
        assert cache.get(key) is None

        found, value = cache.lookup(key)
        assert found is True
        assert value is None

        found, value = cache.lookup(missing)
        assert found is False
        assert value is None
        cache.close()

    def test_lookup_removes_signed_unpicklable_entry(self, tmp_path: Path) -> None:
        cache = PersistentCache(db_path=tmp_path / "cache.db")
        key = CacheKey(CacheKeyType.FUNCTION, "bad")
        key_str = key.to_string()
        raw_blob = b"not a pickle payload"
        signed_blob = CacheIntegrity(tmp_path / "cache.key").sign(key_str, raw_blob)
        now = time.time()

        assert cache.conn is not None
        cache.conn.execute(
            """
            INSERT INTO cache
            (key, key_type, value_hash, value_blob, created_at,
             accessed_at, access_count, dependencies)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?)
            """,
            (
                key_str,
                key.key_type.name,
                stable_digest_hex(raw_blob),
                signed_blob,
                now,
                now,
                "[]",
            ),
        )
        cache.conn.commit()

        found, value = cache.lookup(key)

        assert found is False
        assert value is None
        assert key not in cache
        cache.close()

    def test_put(self, tmp_path: Path) -> None:
        cache = PersistentCache(db_path=tmp_path / "cache.db")
        key = CacheKey(CacheKeyType.FUNCTION, "f1")
        assert cache.put(key, [1, 2, 3]) is True
        assert cache.get(key) == [1, 2, 3]
        cache.close()

    def test_put_records_stable_metadata_value_hash(self, tmp_path: Path) -> None:
        cache = PersistentCache(db_path=tmp_path / "cache.db")
        key = CacheKey(CacheKeyType.FUNCTION, "f1")
        value = {"data": [1, 2, 3]}

        assert cache.put(key, value) is True

        assert cache.conn is not None
        row = cache.conn.execute(
            "SELECT value_hash FROM cache WHERE key = ?",
            (key.to_string(),),
        ).fetchone()
        assert row is not None
        assert row["value_hash"] == stable_digest_hex(pickle.dumps(value))
        assert len(row["value_hash"]) == 64
        cache.close()

    def test_remove(self, tmp_path: Path) -> None:
        cache = PersistentCache(db_path=tmp_path / "cache.db")
        key = CacheKey(CacheKeyType.FUNCTION, "f1")
        cache.put(key, 1)
        assert cache.remove(key) is True
        assert cache.remove(key) is False
        cache.close()

    def test_invalidate_by_type(self, tmp_path: Path) -> None:
        cache = PersistentCache(db_path=tmp_path / "cache.db")
        k1 = CacheKey(CacheKeyType.FUNCTION, "f1")
        k2 = CacheKey(CacheKeyType.MODULE, "m1")
        cache.put(k1, 1)
        cache.put(k2, 2)
        assert cache.invalidate_by_type(CacheKeyType.FUNCTION) == 1
        assert cache.get(k1) is None
        assert cache.get(k2) == 2
        cache.close()

    def test_invalidate_dependencies(self, tmp_path: Path) -> None:
        cache = PersistentCache(db_path=tmp_path / "cache.db")
        parent = CacheKey(CacheKeyType.MODULE, "m1")
        child1 = CacheKey(CacheKeyType.FUNCTION, "f1")
        child2 = CacheKey(CacheKeyType.FUNCTION, "f2")
        cache.put(parent, 1)
        cache.put(child1, 2, dependencies=[parent])
        cache.put(child2, 3, dependencies=[child1])

        invalidated = cache.invalidate_dependencies(parent)
        assert child1.to_string() in invalidated
        assert child2.to_string() in invalidated
        assert cache.get(parent) == 1
        assert cache.get(child1) is None
        assert cache.get(child2) is None
        cache.close()

    def test_clear(self, tmp_path: Path) -> None:
        cache = PersistentCache(db_path=tmp_path / "cache.db")
        cache.put(CacheKey(CacheKeyType.FUNCTION, "f1"), 1)
        assert cache.clear() == 1
        assert len(cache) == 0
        cache.close()

    def test_cleanup(self, tmp_path: Path) -> None:
        cache = PersistentCache(db_path=tmp_path / "cache.db", max_entries=1)
        k1 = CacheKey(CacheKeyType.FUNCTION, "f1")
        k2 = CacheKey(CacheKeyType.FUNCTION, "f2")
        cache.put(k1, 1)
        cache.put(k2, 2)
        assert cache.conn is not None
        cache.conn.execute("UPDATE cache SET accessed_at = ? WHERE key = ?", (1.0, k1.to_string()))
        cache.conn.execute("UPDATE cache SET accessed_at = ? WHERE key = ?", (2.0, k2.to_string()))
        cache.conn.commit()
        assert cache.cleanup() == 1
        assert len(cache) == 1
        cache.close()

    def test_stats(self, tmp_path: Path) -> None:
        cache = PersistentCache(db_path=tmp_path / "cache.db")
        cache.put(CacheKey(CacheKeyType.FUNCTION, "f1"), 1)
        stats = cache.stats()
        assert stats["entry_count"] == 1
        assert stats["by_type"] == {"FUNCTION": 1}
        cache.close()
