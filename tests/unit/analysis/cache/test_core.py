import pytest
from pathlib import Path
import time
import os
import tempfile
from pysymex.analysis.cache.core import (
    CacheKeyType,
    CacheKey,
    hash_bytecode,
    hash_function,
    hash_file,
    hash_dict,
    LRUCache,
    CacheEntry,
    PersistentCache,
    TieredCache,
)


class TestCacheKeyType:
    """Test suite for pysymex.analysis.cache.core.CacheKeyType."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert CacheKeyType.FUNCTION.name == "FUNCTION"


class TestCacheKey:
    """Test suite for pysymex.analysis.cache.core.CacheKey."""

    def test_to_string(self) -> None:
        """Test to_string behavior."""
        key = CacheKey(CacheKeyType.FUNCTION, "my_func", "1.5")
        assert key.to_string() == "FUNCTION:my_func:1.5"

    def test_from_string(self) -> None:
        """Test from_string behavior."""
        key = CacheKey.from_string("MODULE:my_module:2.0")
        assert key.key_type == CacheKeyType.MODULE
        assert key.identifier == "my_module"
        assert key.version == "2.0"

        key2 = CacheKey.from_string("CUSTOM:my_custom")
        assert key2.key_type == CacheKeyType.CUSTOM
        assert key2.identifier == "my_custom"
        assert key2.version == "1.0"

        with pytest.raises(ValueError):
            CacheKey.from_string("invalid_format")


def test_hash_bytecode() -> None:
    """Test hash_bytecode behavior."""
    b1 = b"abc"
    b2 = b"abc"
    assert hash_bytecode(b1) == hash_bytecode(b2)
    assert hash_bytecode(b1) != hash_bytecode(b"def")


def test_hash_function() -> None:
    """Test hash_function behavior."""

    def my_func() -> None:
        pass

    h1 = hash_function("my_func", my_func.__code__, "sig1")
    h2 = hash_function("my_func", my_func.__code__, "sig1")
    h3 = hash_function("my_func2", my_func.__code__, "sig1")
    assert h1 == h2
    assert h1 != h3

    h4 = hash_function("my_func", b"code_bytes", "sig2")
    h5 = hash_function("my_func", b"code_bytes", "sig2")
    assert h4 == h5


def test_hash_file(tmp_path: Path) -> None:
    """Test hash_file behavior."""
    file = tmp_path / "test.txt"
    file.write_bytes(b"content")
    h1 = hash_file(file)
    file.write_bytes(b"content")
    h2 = hash_file(file)
    file.write_bytes(b"changed")
    h3 = hash_file(file)
    assert h1 == h2
    assert h1 != h3


def test_hash_dict() -> None:
    """Test hash_dict behavior."""
    d1 = {"a": 1, "b": 2}
    d2 = {"b": 2, "a": 1}
    assert hash_dict(d1) == hash_dict(d2)
    assert hash_dict(d1) != hash_dict({"a": 1})


class TestLRUCache:
    """Test suite for pysymex.analysis.cache.core.LRUCache."""

    def test_get(self) -> None:
        """Test get behavior."""
        cache = LRUCache[str, int]()
        cache.put("a", 1)
        assert cache.get("a") == 1
        assert cache.get("b", 42) == 42
        assert cache.get("b") is None

    def test_put(self) -> None:
        """Test put behavior."""
        cache = LRUCache[str, int](maxsize=2)
        cache.put("a", 1)
        cache.put("b", 2)
        cache.put("c", 3)
        assert cache.get("a") is None
        assert cache.get("b") == 2
        assert cache.get("c") == 3
        cache.put("b", 4)
        assert cache.get("b") == 4

    def test_remove(self) -> None:
        """Test remove behavior."""
        cache = LRUCache[str, int]()
        cache.put("a", 1)
        assert cache.remove("a") is True
        assert cache.remove("a") is False

    def test_clear(self) -> None:
        """Test clear behavior."""
        cache = LRUCache[str, int]()
        cache.put("a", 1)
        cache.clear()
        assert cache.get("a") is None
        assert len(cache) == 0

    def test_hit_rate(self) -> None:
        """Test hit_rate behavior."""
        cache = LRUCache[str, int]()
        assert cache.hit_rate == 0.0
        cache.put("a", 1)
        cache.get("a")
        cache.get("b")
        assert cache.hit_rate == 0.5

    def test_stats(self) -> None:
        """Test stats behavior."""
        cache = LRUCache[str, int](maxsize=5)
        cache.put("a", 1)
        cache.get("a")
        stats = cache.stats()
        assert stats["size"] == 1
        assert stats["maxsize"] == 5
        assert stats["hits"] == 1
        assert stats["misses"] == 0


class TestCacheEntry:
    """Test suite for pysymex.analysis.cache.core.CacheEntry."""

    def test_age(self) -> None:
        """Test age behavior."""
        now = time.time()
        entry = CacheEntry("k", "t", "h", b"v", now - 10, now, 1, "[]")
        assert entry.age >= 10


class TestPersistentCache:
    """Test suite for pysymex.analysis.cache.core.PersistentCache."""

    def test_close(self, tmp_path: Path) -> None:
        """Test close behavior."""
        cache = PersistentCache(db_path=tmp_path / "cache.db")
        cache.close()
        assert cache._conn is None

    def test_get(self, tmp_path: Path) -> None:
        """Test get behavior."""
        cache = PersistentCache(db_path=tmp_path / "cache.db")
        key = CacheKey(CacheKeyType.FUNCTION, "f1")
        assert cache.get(key) is None
        cache.put(key, {"data": 42})
        assert cache.get(key) == {"data": 42}
        cache.close()

    def test_put(self, tmp_path: Path) -> None:
        """Test put behavior."""
        cache = PersistentCache(db_path=tmp_path / "cache.db")
        key = CacheKey(CacheKeyType.FUNCTION, "f1")
        assert cache.put(key, [1, 2, 3]) is True
        assert cache.get(key) == [1, 2, 3]
        cache.close()

    def test_remove(self, tmp_path: Path) -> None:
        """Test remove behavior."""
        cache = PersistentCache(db_path=tmp_path / "cache.db")
        key = CacheKey(CacheKeyType.FUNCTION, "f1")
        cache.put(key, 1)
        assert cache.remove(key) is True
        assert cache.remove(key) is False
        cache.close()

    def test_invalidate_by_type(self, tmp_path: Path) -> None:
        """Test invalidate_by_type behavior."""
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
        """Test invalidate_dependencies behavior."""
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
        """Test clear behavior."""
        cache = PersistentCache(db_path=tmp_path / "cache.db")
        cache.put(CacheKey(CacheKeyType.FUNCTION, "f1"), 1)
        assert cache.clear() == 1
        assert len(cache) == 0
        cache.close()

    def test_cleanup(self, tmp_path: Path) -> None:
        """Test cleanup behavior."""
        cache = PersistentCache(db_path=tmp_path / "cache.db", max_entries=1)
        k1 = CacheKey(CacheKeyType.FUNCTION, "f1")
        k2 = CacheKey(CacheKeyType.FUNCTION, "f2")
        cache.put(k1, 1)
        time.sleep(0.01)
        cache.put(k2, 2)
        assert cache.cleanup() == 1
        assert len(cache) == 1
        cache.close()

    def test_stats(self, tmp_path: Path) -> None:
        """Test stats behavior."""
        cache = PersistentCache(db_path=tmp_path / "cache.db")
        cache.put(CacheKey(CacheKeyType.FUNCTION, "f1"), 1)
        stats = cache.stats()
        assert stats["entry_count"] == 1
        assert stats["by_type"] == {"FUNCTION": 1}
        cache.close()


class TestTieredCache:
    """Test suite for pysymex.analysis.cache.core.TieredCache."""

    def test_get(self, tmp_path: Path) -> None:
        """Test get behavior."""
        cache = TieredCache(db_path=tmp_path / "cache.db")
        key = CacheKey(CacheKeyType.FUNCTION, "f1")
        cache.put(key, 42)
        cache.memory.clear()
        assert cache.get(key) == 42
        assert cache.memory.get(key.to_string()) == 42
        cache.close()

    def test_put(self, tmp_path: Path) -> None:
        """Test put behavior."""
        cache = TieredCache(db_path=tmp_path / "cache.db")
        key = CacheKey(CacheKeyType.FUNCTION, "f1")
        cache.put(key, 42, persist=False)
        assert cache.memory.get(key.to_string()) == 42
        assert cache.persistent.get(key) is None

        cache.put(key, 43, persist=True)
        assert cache.persistent.get(key) == 43
        cache.close()

    def test_remove(self, tmp_path: Path) -> None:
        """Test remove behavior."""
        cache = TieredCache(db_path=tmp_path / "cache.db")
        key = CacheKey(CacheKeyType.FUNCTION, "f1")
        cache.put(key, 42)
        assert cache.remove(key) is True
        assert cache.memory.get(key.to_string()) is None
        assert cache.persistent.get(key) is None
        cache.close()

    def test_clear(self, tmp_path: Path) -> None:
        """Test clear behavior."""
        cache = TieredCache(db_path=tmp_path / "cache.db")
        cache.put(CacheKey(CacheKeyType.FUNCTION, "f1"), 42)
        cache.clear()
        assert len(cache.memory) == 0
        assert len(cache.persistent) == 0
        cache.close()

    def test_close(self, tmp_path: Path) -> None:
        """Test close behavior."""
        cache = TieredCache(db_path=tmp_path / "cache.db")
        cache.close()
        assert cache.persistent._conn is None

    def test_stats(self, tmp_path: Path) -> None:
        """Test stats behavior."""
        cache = TieredCache(db_path=tmp_path / "cache.db")
        stats = cache.stats()
        assert "memory" in stats
        assert "persistent" in stats
        cache.close()
