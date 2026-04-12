import pytest
from pathlib import Path
from pysymex.analysis.cache.core import CacheKey, CacheKeyType, TieredCache
from pysymex.analysis.cache.invalidation import (
    InvalidationStrategy, InvalidationRule, SmartInvalidator, FileCache
)

class TestInvalidationStrategy:
    """Test suite for pysymex.analysis.cache.invalidation.InvalidationStrategy."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert InvalidationStrategy.IMMEDIATE.name == "IMMEDIATE"

class TestInvalidationRule:
    """Test suite for pysymex.analysis.cache.invalidation.InvalidationRule."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        rule = InvalidationRule("foo*", InvalidationStrategy.IMMEDIATE)
        assert rule.key_pattern == "foo*"
        assert rule.strategy == InvalidationStrategy.IMMEDIATE

class TestSmartInvalidator:
    """Test suite for pysymex.analysis.cache.invalidation.SmartInvalidator."""
    def test_add_rule(self, tmp_path: Path) -> None:
        """Test add_rule behavior."""
        cache = TieredCache(db_path=tmp_path / "cache.db")
        invalidator = SmartInvalidator(cache)
        rule = InvalidationRule("*", InvalidationStrategy.LAZY)
        invalidator.add_rule(rule)
        assert len(invalidator.rules) == 1
        cache.close()

    def test_on_change(self, tmp_path: Path) -> None:
        """Test on_change behavior."""
        cache = TieredCache(db_path=tmp_path / "cache.db")
        invalidator = SmartInvalidator(cache)
        rule = InvalidationRule("MODULE:*", InvalidationStrategy.IMMEDIATE)
        invalidator.add_rule(rule)
        
        key = CacheKey(CacheKeyType.MODULE, "foo")
        cache.put(key, 42)
        invalidated = invalidator.on_change(key)
        assert key.to_string() in invalidated
        assert cache.get(key) is None
        cache.close()

    def test_is_stale(self, tmp_path: Path) -> None:
        """Test is_stale behavior."""
        cache = TieredCache(db_path=tmp_path / "cache.db")
        invalidator = SmartInvalidator(cache)
        rule = InvalidationRule("MODULE:*", InvalidationStrategy.TIME_BASED, max_age_seconds=0.01)
        invalidator.add_rule(rule)
        
        key = CacheKey(CacheKeyType.MODULE, "foo")
        invalidator.mark_fresh(key)
        assert invalidator.is_stale(key) is False
        
        # We need to sleep to test the time-based stale
        import time
        time.sleep(0.02)
        assert invalidator.is_stale(key) is True
        cache.close()

    def test_mark_fresh(self, tmp_path: Path) -> None:
        """Test mark_fresh behavior."""
        cache = TieredCache(db_path=tmp_path / "cache.db")
        invalidator = SmartInvalidator(cache)
        key = CacheKey(CacheKeyType.MODULE, "foo")
        
        # Test LAZY invalidation
        rule = InvalidationRule("MODULE:*", InvalidationStrategy.LAZY)
        invalidator.add_rule(rule)
        
        invalidator.on_change(key)
        assert invalidator.is_stale(key) is True
        
        invalidator.mark_fresh(key)
        assert invalidator.is_stale(key) is False
        cache.close()

class TestFileCache:
    """Test suite for pysymex.analysis.cache.invalidation.FileCache."""
    def test_close(self, tmp_path: Path) -> None:
        """Test close behavior."""
        cache = TieredCache(db_path=tmp_path / "cache.db")
        fc = FileCache(cache)
        fc.close()
        assert cache.persistent._conn is None

    def test_get_or_analyze(self, tmp_path: Path) -> None:
        """Test get_or_analyze behavior."""
        cache = TieredCache(db_path=tmp_path / "cache.db")
        fc = FileCache(cache)
        
        file_path = tmp_path / "test.py"
        file_path.write_bytes(b"content")
        
        called = 0
        def analyzer(p: Path) -> str:
            nonlocal called
            called += 1
            return "result"
            
        res, was_cached = fc.get_or_analyze(file_path, analyzer)
        assert res == "result"
        assert was_cached is False
        assert called == 1
        
        res, was_cached = fc.get_or_analyze(file_path, analyzer)
        assert res == "result"
        assert was_cached is True
        assert called == 1
        fc.close()

    def test_invalidate(self, tmp_path: Path) -> None:
        """Test invalidate behavior."""
        cache = TieredCache(db_path=tmp_path / "cache.db")
        fc = FileCache(cache)
        
        file_path = tmp_path / "test.py"
        file_path.write_bytes(b"content")
        
        fc.get_or_analyze(file_path, lambda p: "result")
        fc.invalidate(file_path)
        
        called = False
        def analyzer(p: Path) -> str:
            nonlocal called
            called = True
            return "new_result"
            
        res, was_cached = fc.get_or_analyze(file_path, analyzer)
        assert res == "new_result"
        assert was_cached is False
        assert called is True
        fc.close()