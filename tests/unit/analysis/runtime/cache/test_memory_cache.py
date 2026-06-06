"""Tests for in-memory cache implementations."""

from __future__ import annotations

import pytest

from pysymex.analysis.runtime.cache.memory import LRUCache


class TestLRUCache:
    """Test suite for pysymex.analysis.runtime.cache.memory.LRUCache."""

    def test_get(self) -> None:
        cache = LRUCache[str, int]()
        cache.put("a", 1)
        assert cache.get("a") == 1
        assert cache.get("b", 42) == 42
        assert cache.get("b") is None

    def test_lookup_distinguishes_cached_none_from_miss(self) -> None:
        cache = LRUCache[str, object]()
        cache.put("a", None)

        found, value = cache.lookup("a")
        assert found is True
        assert value is None

        found, value = cache.lookup("b")
        assert found is False
        assert value is None

    def test_put(self) -> None:
        cache = LRUCache[str, int](maxsize=2)
        cache.put("a", 1)
        cache.put("b", 2)
        cache.put("c", 3)
        assert cache.get("a") is None
        assert cache.get("b") == 2
        assert cache.get("c") == 3
        cache.put("b", 4)
        assert cache.get("b") == 4

    def test_zero_size_cache_does_not_store_entries(self) -> None:
        cache = LRUCache[str, int](maxsize=0)
        cache.put("a", 1)

        found, value = cache.lookup("a")
        assert found is False
        assert value is None
        assert len(cache) == 0

    def test_negative_size_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            LRUCache[str, int](maxsize=-1)

    def test_remove(self) -> None:
        cache = LRUCache[str, int]()
        cache.put("a", 1)
        assert cache.remove("a") is True
        assert cache.remove("a") is False

    def test_clear(self) -> None:
        cache = LRUCache[str, int]()
        cache.put("a", 1)
        cache.clear()
        assert cache.get("a") is None
        assert len(cache) == 0

    def test_hit_rate(self) -> None:
        cache = LRUCache[str, int]()
        assert cache.hit_rate == 0.0
        cache.put("a", 1)
        cache.get("a")
        cache.get("b")
        assert cache.hit_rate == 0.5

    def test_stats(self) -> None:
        cache = LRUCache[str, int](maxsize=5)
        cache.put("a", 1)
        cache.get("a")
        stats = cache.stats()
        assert stats["size"] == 1
        assert stats["maxsize"] == 5
        assert stats["hits"] == 1
        assert stats["misses"] == 0
