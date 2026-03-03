"""Tests for persistent caching and parallel analysis."""

import pytest

import time

import tempfile

import threading

from pathlib import Path

from concurrent.futures import ThreadPoolExecutor


from pysymex.analysis.cache import (
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
    AnalysisTask,
    AnalysisResult,
    ProgressReporter,
    ParallelAnalyzer,
    CachedAnalysis,
    InvalidationStrategy,
    InvalidationRule,
    SmartInvalidator,
    FileCache,
)


class TestCacheKey:
    """Tests for CacheKey."""

    def test_create_key(self):
        """Test creating a cache key."""

        key = CacheKey(CacheKeyType.FUNCTION, "my_func")

        assert key.key_type == CacheKeyType.FUNCTION

        assert key.identifier == "my_func"

        assert key.version == "1.0"

    def test_key_with_version(self):
        """Test key with custom version."""

        key = CacheKey(CacheKeyType.BYTECODE, "code123", version="2.0")

        assert key.version == "2.0"

    def test_key_to_string(self):
        """Test converting key to string."""

        key = CacheKey(CacheKeyType.SUMMARY, "summary1", "1.5")

        s = key.to_string()

        assert s == "SUMMARY:summary1:1.5"

    def test_key_from_string(self):
        """Test parsing key from string."""

        key = CacheKey.from_string("VERIFICATION:verify1:1.0")

        assert key.key_type == CacheKeyType.VERIFICATION

        assert key.identifier == "verify1"

        assert key.version == "1.0"

    def test_key_hashable(self):
        """Test that keys are hashable."""

        key1 = CacheKey(CacheKeyType.FUNCTION, "func1")

        key2 = CacheKey(CacheKeyType.FUNCTION, "func1")

        assert hash(key1) == hash(key2)

        assert key1 == key2

    def test_key_in_dict(self):
        """Test using keys in dictionaries."""

        d = {}

        key = CacheKey(CacheKeyType.CUSTOM, "custom1")

        d[key] = "value"

        assert d[key] == "value"


class TestHashing:
    """Tests for hash functions."""

    def test_hash_bytecode(self):
        """Test hashing bytecode."""

        code = b"hello world"

        h = hash_bytecode(code)

        assert len(h) == 64

        assert h == hash_bytecode(code)

    def test_hash_function(self):
        """Test hashing function."""

        h1 = hash_function("foo", b"code1", "int -> str")

        h2 = hash_function("foo", b"code1", "int -> str")

        h3 = hash_function("bar", b"code1", "int -> str")

        assert h1 == h2

        assert h1 != h3

    def test_hash_file(self, tmp_path):
        """Test hashing file."""

        f = tmp_path / "test.py"

        f.write_text("print('hello')")

        h = hash_file(f)

        assert len(h) == 64

    def test_hash_dict(self):
        """Test hashing dictionary."""

        d1 = {"a": 1, "b": 2}

        d2 = {"b": 2, "a": 1}

        h1 = hash_dict(d1)

        h2 = hash_dict(d2)

        assert h1 == h2


class TestLRUCache:
    """Tests for LRUCache."""

    def test_basic_put_get(self):
        """Test basic put and get."""

        cache = LRUCache[str, int](maxsize=10)

        cache.put("a", 1)

        assert cache.get("a") == 1

    def test_get_missing(self):
        """Test getting missing key."""

        cache = LRUCache[str, int]()

        assert cache.get("missing") is None

        assert cache.get("missing", -1) == -1

    def test_maxsize_eviction(self):
        """Test eviction when maxsize exceeded."""

        cache = LRUCache[str, int](maxsize=3)

        cache.put("a", 1)

        cache.put("b", 2)

        cache.put("c", 3)

        cache.put("d", 4)

        assert cache.get("a") is None

        assert cache.get("d") == 4

        assert len(cache) == 3

    def test_lru_order(self):
        """Test LRU ordering."""

        cache = LRUCache[str, int](maxsize=3)

        cache.put("a", 1)

        cache.put("b", 2)

        cache.put("c", 3)

        cache.get("a")

        cache.put("d", 4)

        assert cache.get("a") == 1

        assert cache.get("b") is None

    def test_remove(self):
        """Test removing key."""

        cache = LRUCache[str, int]()

        cache.put("a", 1)

        assert cache.remove("a")

        assert "a" not in cache

        assert not cache.remove("a")

    def test_clear(self):
        """Test clearing cache."""

        cache = LRUCache[str, int]()

        cache.put("a", 1)

        cache.put("b", 2)

        cache.clear()

        assert len(cache) == 0

    def test_hit_rate(self):
        """Test hit rate tracking."""

        cache = LRUCache[str, int]()

        cache.put("a", 1)

        cache.get("a")

        cache.get("a")

        cache.get("b")

        assert cache.hit_rate == 2 / 3

    def test_stats(self):
        """Test statistics."""

        cache = LRUCache[str, int](maxsize=100)

        cache.put("x", 1)

        cache.get("x")

        cache.get("y")

        stats = cache.stats()

        assert stats["size"] == 1

        assert stats["maxsize"] == 100

        assert stats["hits"] == 1

        assert stats["misses"] == 1

    def test_thread_safety(self):
        """Test thread safety."""

        cache = LRUCache[str, int](maxsize=1000)

        errors = []

        def worker(thread_id):
            try:
                for i in range(100):
                    key = f"t{thread_id}_k{i}"

                    cache.put(key, i)

                    cache.get(key)

            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        assert not errors


class TestPersistentCache:
    """Tests for PersistentCache."""

    def test_create_cache(self, tmp_path):
        """Test creating persistent cache."""

        db = tmp_path / "test.db"

        cache = PersistentCache(db_path=db)

        assert db.exists()

    def test_put_get(self, tmp_path):
        """Test put and get."""

        db = tmp_path / "test.db"

        cache = PersistentCache(db_path=db)

        key = CacheKey(CacheKeyType.FUNCTION, "func1")

        cache.put(key, {"result": 42})

        result = cache.get(key)

        assert result == {"result": 42}

    def test_get_missing(self, tmp_path):
        """Test getting missing key."""

        db = tmp_path / "test.db"

        cache = PersistentCache(db_path=db)

        key = CacheKey(CacheKeyType.FUNCTION, "missing")

        assert cache.get(key) is None

    def test_persistence(self, tmp_path):
        """Test that cache persists across instances."""

        db = tmp_path / "test.db"

        key = CacheKey(CacheKeyType.VERIFICATION, "verify1")

        cache1 = PersistentCache(db_path=db)

        cache1.put(key, "persisted_value")

        cache2 = PersistentCache(db_path=db)

        result = cache2.get(key)

        assert result == "persisted_value"

    def test_remove(self, tmp_path):
        """Test removing entry."""

        db = tmp_path / "test.db"

        cache = PersistentCache(db_path=db)

        key = CacheKey(CacheKeyType.BYTECODE, "bc1")

        cache.put(key, "value")

        assert cache.remove(key)

        assert cache.get(key) is None

    def test_invalidate_by_type(self, tmp_path):
        """Test invalidating by type."""

        db = tmp_path / "test.db"

        cache = PersistentCache(db_path=db)

        cache.put(CacheKey(CacheKeyType.FUNCTION, "f1"), "v1")

        cache.put(CacheKey(CacheKeyType.FUNCTION, "f2"), "v2")

        cache.put(CacheKey(CacheKeyType.BYTECODE, "b1"), "v3")

        removed = cache.invalidate_by_type(CacheKeyType.FUNCTION)

        assert removed == 2

        assert cache.get(CacheKey(CacheKeyType.BYTECODE, "b1")) == "v3"

    def test_clear(self, tmp_path):
        """Test clearing cache."""

        db = tmp_path / "test.db"

        cache = PersistentCache(db_path=db)

        for i in range(5):
            cache.put(CacheKey(CacheKeyType.CUSTOM, f"k{i}"), i)

        cleared = cache.clear()

        assert cleared == 5

        assert len(cache) == 0

    def test_cleanup_old(self, tmp_path):
        """Test cleanup of old entries."""

        db = tmp_path / "test.db"

        cache = PersistentCache(db_path=db, max_age_days=0)

        key = CacheKey(CacheKeyType.SUMMARY, "old")

        cache.put(key, "old_value")

        with cache._connect() as conn:
            conn.execute("UPDATE cache SET created_at = 0 WHERE key = ?", (key.to_string(),))

        removed = cache.cleanup()

        assert removed >= 1

    def test_stats(self, tmp_path):
        """Test statistics."""

        db = tmp_path / "test.db"

        cache = PersistentCache(db_path=db)

        cache.put(CacheKey(CacheKeyType.FUNCTION, "f1"), 1)

        cache.put(CacheKey(CacheKeyType.FUNCTION, "f2"), 2)

        cache.put(CacheKey(CacheKeyType.BYTECODE, "b1"), 3)

        stats = cache.stats()

        assert stats["entry_count"] == 3

        assert stats["by_type"]["FUNCTION"] == 2

        assert stats["by_type"]["BYTECODE"] == 1

    def test_contains(self, tmp_path):
        """Test contains check."""

        db = tmp_path / "test.db"

        cache = PersistentCache(db_path=db)

        key = CacheKey(CacheKeyType.MODULE, "mod1")

        assert key not in cache

        cache.put(key, "value")

        assert key in cache


class TestTieredCache:
    """Tests for TieredCache."""

    def test_memory_hit(self, tmp_path):
        """Test memory cache hit."""

        db = tmp_path / "test.db"

        cache = TieredCache(memory_size=100, db_path=db)

        key = CacheKey(CacheKeyType.FUNCTION, "func")

        cache.put(key, "value")

        result = cache.get(key)

        assert result == "value"

    def test_promote_from_disk(self, tmp_path):
        """Test promoting from disk to memory."""

        db = tmp_path / "test.db"

        key = CacheKey(CacheKeyType.SUMMARY, "sum1")

        cache1 = TieredCache(memory_size=100, db_path=db)

        cache1.put(key, "disk_value")

        cache2 = TieredCache(memory_size=100, db_path=db)

        result = cache2.get(key)

        assert result == "disk_value"

        assert key.to_string() in cache2.memory

    def test_remove_both(self, tmp_path):
        """Test removing from both caches."""

        db = tmp_path / "test.db"

        cache = TieredCache(db_path=db)

        key = CacheKey(CacheKeyType.BYTECODE, "bc1")

        cache.put(key, "value")

        cache.remove(key)

        assert cache.get(key) is None

    def test_clear_both(self, tmp_path):
        """Test clearing both caches."""

        db = tmp_path / "test.db"

        cache = TieredCache(db_path=db)

        cache.put(CacheKey(CacheKeyType.FUNCTION, "f1"), 1)

        cache.put(CacheKey(CacheKeyType.FUNCTION, "f2"), 2)

        cache.clear()

        assert len(cache.memory) == 0

        assert len(cache.persistent) == 0

    def test_stats_combined(self, tmp_path):
        """Test combined statistics."""

        db = tmp_path / "test.db"

        cache = TieredCache(memory_size=50, db_path=db)

        cache.put(CacheKey(CacheKeyType.CUSTOM, "c1"), 1)

        stats = cache.stats()

        assert "memory" in stats

        assert "persistent" in stats


class TestProgressReporter:
    """Tests for ProgressReporter."""

    def test_set_total(self):
        """Test setting total."""

        reporter = ProgressReporter()

        reporter.set_total(100)

        assert reporter.total == 100

        assert reporter.completed == 0

    def test_report_complete(self):
        """Test reporting completion."""

        reporter = ProgressReporter()

        reporter.set_total(10)

        reporter.report_complete()

        reporter.report_complete(success=False)

        assert reporter.completed == 2

        assert reporter.failed == 1

    def test_progress(self):
        """Test progress calculation."""

        reporter = ProgressReporter()

        reporter.set_total(4)

        reporter.report_complete()

        reporter.report_complete()

        assert reporter.progress == 0.5

    def test_format_progress(self):
        """Test progress formatting."""

        reporter = ProgressReporter()

        reporter.set_total(10)

        reporter.report_complete()

        reporter.report_complete(success=False)

        formatted = reporter.format_progress()

        assert "[2/10]" in formatted

        assert "20.0%" in formatted

        assert "1 failed" in formatted

    def test_callback(self):
        """Test progress callback."""

        reporter = ProgressReporter()

        reporter.set_total(5)

        progress_values = []

        reporter.on_progress(lambda c, t, f: progress_values.append((c, t, f)))

        reporter.report_complete()

        reporter.report_complete()

        assert (1, 5, 0) in progress_values

        assert (2, 5, 0) in progress_values


class TestAnalysisTask:
    """Tests for AnalysisTask."""

    def test_create_task(self):
        """Test creating task."""

        task = AnalysisTask(
            task_id="t1",
            target="target_data",
            priority=10,
        )

        assert task.task_id == "t1"

        assert task.priority == 10

    def test_task_with_dependencies(self):
        """Test task with dependencies."""

        task = AnalysisTask(
            task_id="t2",
            target="data",
            dependencies=["t1"],
        )

        assert "t1" in task.dependencies

    def test_task_ordering(self):
        """Test task ordering by priority."""

        t1 = AnalysisTask("t1", "data", priority=5)

        t2 = AnalysisTask("t2", "data", priority=10)

        assert t2 < t1


class TestParallelAnalyzer:
    """Tests for ParallelAnalyzer."""

    def test_analyze_simple(self):
        """Test simple parallel analysis."""

        analyzer = ParallelAnalyzer(max_workers=2)

        tasks = [AnalysisTask(f"t{i}", i) for i in range(5)]

        results = analyzer.analyze_batch(
            tasks,
            lambda x: x * 2,
        )

        assert len(results) == 5

        assert all(r.success for r in results)

    def test_analyze_with_error(self):
        """Test analysis with errors."""

        analyzer = ParallelAnalyzer(max_workers=2)

        def may_fail(x):
            if x == 2:
                raise ValueError("Error on 2")

            return x

        tasks = [AnalysisTask(f"t{i}", i) for i in range(5)]

        results = analyzer.analyze_batch(tasks, may_fail)

        successes = [r for r in results if r.success]

        failures = [r for r in results if not r.success]

        assert len(successes) == 4

        assert len(failures) == 1

        assert "Error on 2" in failures[0].error

    def test_analyze_with_dependencies(self):
        """Test analysis with dependencies."""

        analyzer = ParallelAnalyzer(max_workers=2)

        execution_order = []

        def track_order(x):
            execution_order.append(x)

            return x

        tasks = [
            AnalysisTask("t1", "a"),
            AnalysisTask("t2", "b", dependencies=["t1"]),
            AnalysisTask("t3", "c", dependencies=["t2"]),
        ]

        analyzer.analyze_batch(tasks, track_order)

        assert execution_order.index("a") < execution_order.index("b")

        assert execution_order.index("b") < execution_order.index("c")

    def test_progress_tracking(self):
        """Test progress is tracked."""

        analyzer = ParallelAnalyzer(max_workers=2)

        tasks = [AnalysisTask(f"t{i}", i) for i in range(10)]

        analyzer.analyze_batch(tasks, lambda x: x)

        assert analyzer.progress.completed == 10

        assert analyzer.progress.failed == 0


class TestCachedAnalysis:
    """Tests for CachedAnalysis."""

    def test_caching_works(self, tmp_path):
        """Test that caching works."""

        db = tmp_path / "test.db"

        cache = TieredCache(db_path=db)

        call_count = [0]

        def analyze(x):
            call_count[0] += 1

            return x * 2

        cached = CachedAnalysis(
            analyze,
            lambda x: CacheKey(CacheKeyType.CUSTOM, str(x)),
            cache,
        )

        result1 = cached(5)

        assert result1 == 10

        assert call_count[0] == 1

        result2 = cached(5)

        assert result2 == 10

        assert call_count[0] == 1

    def test_hit_rate(self, tmp_path):
        """Test hit rate tracking."""

        db = tmp_path / "test.db"

        cache = TieredCache(db_path=db)

        cached = CachedAnalysis(
            lambda x: x,
            lambda x: CacheKey(CacheKeyType.CUSTOM, str(x)),
            cache,
        )

        cached(1)

        cached(1)

        cached(1)

        cached(2)

        assert cached.hit_rate == 0.5

    def test_invalidate(self, tmp_path):
        """Test invalidation."""

        db = tmp_path / "test.db"

        cache = TieredCache(db_path=db)

        call_count = [0]

        cached = CachedAnalysis(
            lambda x: (call_count.__setitem__(0, call_count[0] + 1), x)[1],
            lambda x: CacheKey(CacheKeyType.CUSTOM, str(x)),
            cache,
        )

        cached(5)

        cached(5)

        cached.invalidate(5)

        cached(5)

        assert call_count[0] == 2


class TestSmartInvalidator:
    """Tests for SmartInvalidator."""

    def test_immediate_invalidation(self, tmp_path):
        """Test immediate invalidation strategy."""

        db = tmp_path / "test.db"

        cache = TieredCache(db_path=db)

        key = CacheKey(CacheKeyType.FUNCTION, "func1")

        cache.put(key, "value")

        invalidator = SmartInvalidator(cache)

        invalidator.add_rule(
            InvalidationRule(
                key_pattern="FUNCTION:*",
                strategy=InvalidationStrategy.IMMEDIATE,
            )
        )

        invalidator.on_change(key)

        assert cache.get(key) is None

    def test_lazy_invalidation(self, tmp_path):
        """Test lazy invalidation strategy."""

        db = tmp_path / "test.db"

        cache = TieredCache(db_path=db)

        key = CacheKey(CacheKeyType.SUMMARY, "sum1")

        cache.put(key, "value")

        invalidator = SmartInvalidator(cache)

        invalidator.add_rule(
            InvalidationRule(
                key_pattern="SUMMARY:*",
                strategy=InvalidationStrategy.LAZY,
            )
        )

        invalidator.on_change(key)

        assert invalidator.is_stale(key)

        assert cache.get(key) == "value"

    def test_mark_fresh(self, tmp_path):
        """Test marking as fresh."""

        db = tmp_path / "test.db"

        cache = TieredCache(db_path=db)

        key = CacheKey(CacheKeyType.BYTECODE, "bc1")

        invalidator = SmartInvalidator(cache)

        invalidator._stale.add(key.to_string())

        invalidator.mark_fresh(key)

        assert not invalidator.is_stale(key)


class TestFileCache:
    """Tests for FileCache."""

    def test_cache_file_analysis(self, tmp_path):
        """Test caching file analysis."""

        f = tmp_path / "test.py"

        f.write_text("x = 1")

        db = tmp_path / "cache.db"

        file_cache = FileCache(TieredCache(db_path=db))

        call_count = [0]

        def analyze(path):
            call_count[0] += 1

            return {"lines": len(path.read_text().splitlines())}

        result1, cached1 = file_cache.get_or_analyze(f, analyze)

        result2, cached2 = file_cache.get_or_analyze(f, analyze)

        assert result1 == {"lines": 1}

        assert not cached1

        assert cached2

        assert call_count[0] == 1

    def test_invalidate_on_change(self, tmp_path):
        """Test invalidation on file change."""

        f = tmp_path / "test.py"

        f.write_text("version 1")

        db = tmp_path / "cache.db"

        file_cache = FileCache(TieredCache(db_path=db))

        call_count = [0]

        def analyze(path):
            call_count[0] += 1

            return path.read_text()

        file_cache.get_or_analyze(f, analyze)

        f.write_text("version 2")

        result, cached = file_cache.get_or_analyze(f, analyze)

        assert result == "version 2"

        assert not cached

        assert call_count[0] == 2

    def test_explicit_invalidate(self, tmp_path):
        """Test explicit invalidation."""

        f = tmp_path / "test.py"

        f.write_text("content")

        db = tmp_path / "cache.db"

        file_cache = FileCache(TieredCache(db_path=db))

        call_count = [0]

        def analyze(path):
            call_count[0] += 1

            return "analyzed"

        file_cache.get_or_analyze(f, analyze)

        file_cache.invalidate(f)

        file_cache.get_or_analyze(f, analyze)

        assert call_count[0] == 2
