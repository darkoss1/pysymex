from pathlib import Path
from pysymex.analysis.runtime.cache.cached import CachedAnalysis
from pysymex.analysis.runtime.cache.keying import CacheKey, CacheKeyType
from pysymex.analysis.runtime.cache.models import AnalysisResult, AnalysisTask
from pysymex.analysis.runtime.cache.parallel import ParallelAnalyzer
from pysymex.analysis.runtime.cache.progress import ProgressReporter
from pysymex.analysis.runtime.cache.tiered import TieredCache


class TestAnalysisTask:
    """Test suite for pysymex.analysis.runtime.cache.models.AnalysisTask."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        task = AnalysisTask("t1", "target_obj", 10, ["d1"])
        assert task.task_id == "t1"
        assert task.target == "target_obj"
        assert task.priority == 10
        assert task.dependencies == ["d1"]

        t2 = AnalysisTask("t2", "obj2", 5)
        assert task < t2


class TestAnalysisResult:
    """Test suite for pysymex.analysis.runtime.cache.models.AnalysisResult."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        res = AnalysisResult("t1", True, result=42, duration=1.5)
        assert res.task_id == "t1"
        assert res.success is True
        assert res.result == 42
        assert res.duration == 1.5


class TestProgressReporter:
    """Test suite for pysymex.analysis.runtime.cache.progress.ProgressReporter."""

    def test_set_total(self) -> None:
        """Test set_total behavior."""
        reporter = ProgressReporter()
        reporter.set_total(10)
        assert reporter.total == 10
        assert reporter.completed == 0
        assert reporter.failed == 0

    def test_report_complete(self) -> None:
        """Test report_complete behavior."""
        reporter = ProgressReporter()
        reporter.set_total(2)
        reporter.report_complete(success=True)
        assert reporter.completed == 1
        assert reporter.failed == 0
        reporter.report_complete(success=False)
        assert reporter.completed == 2
        assert reporter.failed == 1

    def test_on_progress(self) -> None:
        """Test on_progress behavior."""
        reporter = ProgressReporter()
        reporter.set_total(1)
        called = False

        def cb(c: int, t: int, f: int) -> None:
            nonlocal called
            called = True
            assert c == 1 and t == 1 and f == 0

        reporter.on_progress(cb)
        reporter.report_complete()
        assert called is True

    def test_progress(self) -> None:
        """Test progress behavior."""
        reporter = ProgressReporter()
        assert reporter.progress == 0.0
        reporter.set_total(2)
        reporter.report_complete()
        assert reporter.progress == 0.5

    def test_format_progress(self) -> None:
        """Test format_progress behavior."""
        reporter = ProgressReporter()
        reporter.set_total(2)
        reporter.report_complete(success=False)
        formatted = reporter.format_progress()
        assert formatted == "[1/2] 50.0% (1 failed)"


class TestParallelAnalyzer:
    """Test suite for pysymex.analysis.runtime.cache.parallel.ParallelAnalyzer."""

    def test_analyze_batch(self) -> None:
        """Test analyze_batch behavior."""
        analyzer = ParallelAnalyzer(max_workers=2, use_processes=False)
        tasks = [
            AnalysisTask("t1", 1),
            AnalysisTask("t2", 2, dependencies=["t1"]),
            AnalysisTask("t3", 3, dependencies=["t2"]),
        ]

        def mock_analyze(target: object) -> object:
            if target == 2:
                raise ValueError("error")
            return target

        results = analyzer.analyze_batch(tasks, mock_analyze)
        assert len(results) == 3

        res_map = {r.task_id: r for r in results}
        assert res_map["t1"].success is True
        assert res_map["t1"].result == 1

        assert res_map["t2"].success is False
        assert "error" in str(res_map["t2"].error)

        assert res_map["t3"].success is True
        assert res_map["t3"].result == 3

    def test_analyze_batch_reports_missing_dependency_without_running_task(self) -> None:
        analyzer = ParallelAnalyzer(max_workers=2, use_processes=False)
        completed: list[AnalysisResult] = []
        called = False

        def mock_analyze(target: object) -> object:
            nonlocal called
            called = True
            return target

        results = analyzer.analyze_batch(
            [AnalysisTask("t1", 1, dependencies=["missing"])],
            mock_analyze,
            on_complete=completed.append,
        )

        assert called is False
        assert len(results) == 1
        assert results[0].success is False
        assert results[0].error == "Unresolvable dependency"
        assert completed == results
        assert analyzer.progress.completed == 1
        assert analyzer.progress.failed == 1

    def test_analyze_batch_reports_exception_type_for_empty_error_message(self) -> None:
        class EmptyAnalysisError(Exception):
            pass

        analyzer = ParallelAnalyzer(max_workers=1, use_processes=False)

        def mock_analyze(target: object) -> object:
            raise EmptyAnalysisError()

        results = analyzer.analyze_batch([AnalysisTask("t1", object())], mock_analyze)

        assert len(results) == 1
        assert results[0].success is False
        assert results[0].error == "EmptyAnalysisError"
        assert analyzer.progress.completed == 1
        assert analyzer.progress.failed == 1


class TestCachedAnalysis:
    """Test suite for pysymex.analysis.runtime.cache.cached.CachedAnalysis."""

    def test_invalidate(self, tmp_path: Path) -> None:
        """Test invalidate behavior."""

        def dummy(x: object) -> object:
            return x

        def key_fn(x: object) -> CacheKey:
            return CacheKey(CacheKeyType.CUSTOM, str(x))

        cache = TieredCache(db_path=tmp_path / "cache.db")
        cached_fn = CachedAnalysis(dummy, key_fn, cache=cache)
        res1 = cached_fn("test")
        assert res1 == "test"

        cached_fn.invalidate("test")
        assert cached_fn.cache.get(key_fn("test")) is None
        cache.close()

    def test_hit_rate(self, tmp_path: Path) -> None:
        """Test hit_rate behavior."""

        def dummy(x: object) -> object:
            return x

        def key_fn(x: object) -> CacheKey:
            return CacheKey(CacheKeyType.CUSTOM, str(x))

        cache = TieredCache(db_path=tmp_path / "cache.db")
        cached_fn = CachedAnalysis(dummy, key_fn, cache=cache)
        cached_fn("a")
        cached_fn("a")
        assert cached_fn.hit_rate == 0.5
        cache.close()

    def test_none_result_is_cached(self, tmp_path: Path) -> None:
        """None is a valid analysis result, not an implicit cache miss."""
        calls = 0

        def dummy(x: object) -> object:
            nonlocal calls
            calls += 1
            return None

        def key_fn(x: object) -> CacheKey:
            return CacheKey(CacheKeyType.CUSTOM, str(x))

        cache = TieredCache(db_path=tmp_path / "cache.db")
        cached_fn = CachedAnalysis(dummy, key_fn, cache=cache)

        assert cached_fn("a") is None
        assert cached_fn("a") is None
        assert calls == 1
        assert cached_fn.hits == 1
        assert cached_fn.misses == 1
        cache.close()

    def test_stats(self, tmp_path: Path) -> None:
        """Test stats behavior."""

        def dummy(x: object) -> object:
            return x

        def key_fn(x: object) -> CacheKey:
            return CacheKey(CacheKeyType.CUSTOM, str(x))

        cache = TieredCache(db_path=tmp_path / "cache.db")
        cached_fn = CachedAnalysis(dummy, key_fn, cache=cache)
        cached_fn("a")
        stats = cached_fn.stats()
        assert stats["hits"] == 0
        assert stats["misses"] == 1
        cache.close()
