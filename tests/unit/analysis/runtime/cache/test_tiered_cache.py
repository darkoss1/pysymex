"""Tests for tiered cache composition."""

from __future__ import annotations

from pathlib import Path

from pysymex.analysis.runtime.cache.keying import CacheKey, CacheKeyType
from pysymex.analysis.runtime.cache.tiered import TieredCache


class UncacheableValue:
    def __getstate__(self) -> object:
        raise TypeError("not cacheable")


class TestTieredCache:
    """Test suite for pysymex.analysis.runtime.cache.tiered.TieredCache."""

    def test_get(self, tmp_path: Path) -> None:
        cache = TieredCache(db_path=tmp_path / "cache.db")
        key = CacheKey(CacheKeyType.FUNCTION, "f1")
        cache.put(key, 42)
        cache.memory.clear()
        assert cache.get(key) == 42
        assert cache.memory.get(key.to_string()) == 42
        cache.close()

    def test_lookup_distinguishes_cached_none_from_miss(self, tmp_path: Path) -> None:
        cache = TieredCache(db_path=tmp_path / "cache.db")
        key = CacheKey(CacheKeyType.FUNCTION, "f1")
        missing = CacheKey(CacheKeyType.FUNCTION, "missing")

        cache.put(key, None)
        cache.memory.clear()

        found, value = cache.lookup(key)
        assert found is True
        assert value is None

        found, value = cache.memory.lookup(key.to_string())
        assert found is True
        assert value is None

        found, value = cache.lookup(missing)
        assert found is False
        assert value is None
        cache.close()

    def test_put(self, tmp_path: Path) -> None:
        cache = TieredCache(db_path=tmp_path / "cache.db")
        key = CacheKey(CacheKeyType.FUNCTION, "f1")
        cache.put(key, 42, persist=False)
        assert cache.memory.get(key.to_string()) == 42
        assert cache.persistent.get(key) is None

        cache.put(key, 43, persist=True)
        assert cache.persistent.get(key) == 43
        cache.close()

    def test_put_removes_stale_persistent_entry_when_write_fails(self, tmp_path: Path) -> None:
        cache = TieredCache(db_path=tmp_path / "cache.db")
        key = CacheKey(CacheKeyType.FUNCTION, "f1")
        key_str = key.to_string()
        uncacheable = UncacheableValue()

        cache.put(key, "old")
        cache.memory.clear()
        assert cache.get(key) == "old"

        cache.put(key, uncacheable)
        assert cache.memory.get(key_str) is uncacheable

        cache.memory.clear()
        assert cache.get(key) is None
        assert cache.persistent.get(key) is None
        cache.close()

    def test_remove(self, tmp_path: Path) -> None:
        cache = TieredCache(db_path=tmp_path / "cache.db")
        key = CacheKey(CacheKeyType.FUNCTION, "f1")
        cache.put(key, 42)
        assert cache.remove(key) is True
        assert cache.memory.get(key.to_string()) is None
        assert cache.persistent.get(key) is None
        cache.close()

    def test_clear(self, tmp_path: Path) -> None:
        cache = TieredCache(db_path=tmp_path / "cache.db")
        cache.put(CacheKey(CacheKeyType.FUNCTION, "f1"), 42)
        cache.clear()
        assert len(cache.memory) == 0
        assert len(cache.persistent) == 0
        cache.close()

    def test_close(self, tmp_path: Path) -> None:
        cache = TieredCache(db_path=tmp_path / "cache.db")
        cache.close()
        assert cache.persistent.conn is None

    def test_stats(self, tmp_path: Path) -> None:
        cache = TieredCache(db_path=tmp_path / "cache.db")
        stats = cache.stats()
        assert "memory" in stats
        assert "persistent" in stats
        cache.close()
