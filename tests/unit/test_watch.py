"""Tests for pysymex.watch — file watching and incremental analysis."""

from __future__ import annotations

import time
from pathlib import Path

from pysymex.watch import (
    AnalysisCache,
    DependencyTracker,
    FileEvent,
    FileEventType,
    FileState,
    FileWatcher,
    IncrementalAnalyzer,
    WatchModeRunner,
)


class TestFileEventType:
    """Tests for FileEventType enum."""

    def test_created_exists(self) -> None:
        """CREATED member exists."""
        assert FileEventType.CREATED.name == "CREATED"

    def test_modified_exists(self) -> None:
        """MODIFIED member exists."""
        assert FileEventType.MODIFIED.name == "MODIFIED"

    def test_deleted_exists(self) -> None:
        """DELETED member exists."""
        assert FileEventType.DELETED.name == "DELETED"

    def test_renamed_exists(self) -> None:
        """RENAMED member exists."""
        assert FileEventType.RENAMED.name == "RENAMED"


class TestFileState:
    """Tests for FileState dataclass."""

    def test_from_path(self, tmp_path: Path) -> None:
        """from_path creates state from a real file."""
        f = tmp_path / "test.py"
        f.write_text("x = 1", encoding="utf-8")
        state = FileState.from_path(f)
        assert state.path == f
        assert state.size > 0
        assert isinstance(state.content_hash, str)
        assert len(state.content_hash) == 64  # SHA-256 hex

    def test_has_changed_same_content(self, tmp_path: Path) -> None:
        """Same content means no change."""
        f = tmp_path / "test.py"
        f.write_text("x = 1", encoding="utf-8")
        s1 = FileState.from_path(f)
        s2 = FileState.from_path(f)
        assert s1.has_changed(s2) is False

    def test_has_changed_different_content(self, tmp_path: Path) -> None:
        """Different content means changed."""
        f = tmp_path / "test.py"
        f.write_text("x = 1", encoding="utf-8")
        s1 = FileState.from_path(f)
        f.write_text("x = 2", encoding="utf-8")
        s2 = FileState.from_path(f)
        assert s1.has_changed(s2) is True


class TestFileWatcher:
    """Tests for FileWatcher."""

    def test_init(self, tmp_path: Path) -> None:
        """FileWatcher initializes with paths and patterns."""
        watcher = FileWatcher([tmp_path])
        assert watcher.paths == [tmp_path]
        assert watcher.patterns == ["*.py"]

    def test_custom_patterns(self, tmp_path: Path) -> None:
        """Custom patterns are stored."""
        watcher = FileWatcher([tmp_path], patterns=["*.txt"])
        assert watcher.patterns == ["*.txt"]

    def test_on_change_registers_callback(self, tmp_path: Path) -> None:
        """on_change stores the callback."""
        watcher = FileWatcher([tmp_path])
        calls: list[FileEvent] = []
        watcher.on_change(lambda e: calls.append(e))
        assert len(watcher._callbacks) == 1

    def test_start_stop(self, tmp_path: Path) -> None:
        """Watcher can be started and stopped without errors."""
        f = tmp_path / "test.py"
        f.write_text("x = 1", encoding="utf-8")
        watcher = FileWatcher([tmp_path], poll_interval=0.1)
        watcher.start()
        time.sleep(0.2)
        watcher.stop()

    def test_get_matching_files(self, tmp_path: Path) -> None:
        """_get_matching_files finds .py files."""
        (tmp_path / "a.py").write_text("x=1", encoding="utf-8")
        (tmp_path / "b.txt").write_text("y=2", encoding="utf-8")
        watcher = FileWatcher([tmp_path])
        files = watcher._get_matching_files()
        names = {f.name for f in files}
        assert "a.py" in names
        assert "b.txt" not in names

    def test_check_changes_detects_new_file(self, tmp_path: Path) -> None:
        """_check_changes detects newly created files."""
        watcher = FileWatcher([tmp_path])
        watcher._scan_initial()
        (tmp_path / "new.py").write_text("z=3", encoding="utf-8")
        events = watcher._check_changes()
        created = [e for e in events if e.event_type == FileEventType.CREATED]
        assert len(created) >= 1

    def test_check_changes_detects_modification(self, tmp_path: Path) -> None:
        """_check_changes detects modified files."""
        f = tmp_path / "mod.py"
        f.write_text("x=1", encoding="utf-8")
        watcher = FileWatcher([tmp_path])
        watcher._scan_initial()
        f.write_text("x=2", encoding="utf-8")
        events = watcher._check_changes()
        modified = [e for e in events if e.event_type == FileEventType.MODIFIED]
        assert len(modified) >= 1

    def test_check_changes_detects_deletion(self, tmp_path: Path) -> None:
        """_check_changes detects deleted files."""
        f = tmp_path / "del.py"
        f.write_text("x=1", encoding="utf-8")
        watcher = FileWatcher([tmp_path])
        watcher._scan_initial()
        f.unlink()
        events = watcher._check_changes()
        deleted = [e for e in events if e.event_type == FileEventType.DELETED]
        assert len(deleted) >= 1


class TestAnalysisCache:
    """Tests for AnalysisCache dataclass."""

    def test_is_valid_matching_hash(self) -> None:
        """Cache is valid when hashes match."""
        cache = AnalysisCache(file_hash="abc", timestamp=1.0, result="ok")
        assert cache.is_valid("abc") is True

    def test_is_valid_different_hash(self) -> None:
        """Cache is invalid when hashes differ."""
        cache = AnalysisCache(file_hash="abc", timestamp=1.0, result="ok")
        assert cache.is_valid("xyz") is False


class TestIncrementalAnalyzer:
    """Tests for IncrementalAnalyzer."""

    def test_init(self) -> None:
        """IncrementalAnalyzer initializes with optional engine."""
        analyzer = IncrementalAnalyzer()
        assert analyzer.engine is None

    def test_add_dependency(self) -> None:
        """add_dependency records file relationships."""
        analyzer = IncrementalAnalyzer()
        analyzer.add_dependency("a.py", "b.py")
        assert "b.py" in analyzer._dependencies["a.py"]
        assert "a.py" in analyzer._dependents["b.py"]

    def test_get_affected_files(self) -> None:
        """get_affected_files returns transitive dependents."""
        analyzer = IncrementalAnalyzer()
        analyzer.add_dependency("b.py", "a.py")
        analyzer.add_dependency("c.py", "b.py")
        affected = analyzer.get_affected_files("a.py")
        assert "a.py" in affected
        assert "b.py" in affected
        assert "c.py" in affected

    def test_get_cached_missing(self) -> None:
        """get_cached returns None for uncached files."""
        assert IncrementalAnalyzer().get_cached("x.py") is None

    def test_cache_result_and_retrieve(self, tmp_path: Path) -> None:
        """cache_result stores and get_cached retrieves."""
        f = tmp_path / "test.py"
        f.write_text("x=1", encoding="utf-8")
        analyzer = IncrementalAnalyzer()
        analyzer.cache_result(str(f), {"status": "ok"})
        cached = analyzer.get_cached(str(f))
        assert cached is not None
        assert cached.result == {"status": "ok"}

    def test_invalidate(self, tmp_path: Path) -> None:
        """invalidate removes cache for file and dependents."""
        f = tmp_path / "a.py"
        f.write_text("x=1", encoding="utf-8")
        analyzer = IncrementalAnalyzer()
        analyzer.cache_result(str(f), "result")
        invalidated = analyzer.invalidate(str(f))
        assert str(f) in invalidated
        assert analyzer.get_cached(str(f)) is None

    def test_clear_cache(self, tmp_path: Path) -> None:
        """clear_cache removes all entries."""
        f = tmp_path / "a.py"
        f.write_text("x=1", encoding="utf-8")
        analyzer = IncrementalAnalyzer()
        analyzer.cache_result(str(f), "result")
        analyzer.clear_cache()
        assert analyzer.get_cached(str(f)) is None


class TestWatchModeRunner:
    """Tests for WatchModeRunner."""

    def test_init(self, tmp_path: Path) -> None:
        """WatchModeRunner initializes correctly."""
        runner = WatchModeRunner([tmp_path])
        assert runner.paths == [tmp_path]
        assert runner.engine is None

    def test_run_analysis(self, tmp_path: Path) -> None:
        """_run_analysis returns a dict."""
        f = tmp_path / "test.py"
        f.write_text("x=1", encoding="utf-8")
        runner = WatchModeRunner([tmp_path])
        result = runner._run_analysis(f)
        assert isinstance(result, dict)

    def test_stop(self, tmp_path: Path) -> None:
        """stop() sets _running to False."""
        runner = WatchModeRunner([tmp_path])
        runner._running = True
        runner.stop()
        assert runner._running is False


class TestDependencyTracker:
    """Tests for DependencyTracker."""

    def test_init(self) -> None:
        """DependencyTracker initializes with empty state."""
        tracker = DependencyTracker()
        assert tracker._imports == {}

    def test_extract_imports(self, tmp_path: Path) -> None:
        """extract_imports finds import statements."""
        f = tmp_path / "test.py"
        f.write_text("import os\nfrom pathlib import Path\n", encoding="utf-8")
        tracker = DependencyTracker()
        imports = tracker.extract_imports(f)
        assert "os" in imports
        assert "pathlib" in imports

    def test_extract_imports_syntax_error(self, tmp_path: Path) -> None:
        """extract_imports handles syntax errors gracefully."""
        f = tmp_path / "bad.py"
        f.write_text("def broken(:\n", encoding="utf-8")
        tracker = DependencyTracker()
        imports = tracker.extract_imports(f)
        assert isinstance(imports, set)

    def test_resolve_import_file(self, tmp_path: Path) -> None:
        """resolve_import finds a .py file."""
        (tmp_path / "utils.py").write_text("", encoding="utf-8")
        base = tmp_path / "main.py"
        base.write_text("", encoding="utf-8")
        tracker = DependencyTracker()
        result = tracker.resolve_import("utils", base)
        assert result is not None
        assert result.name == "utils.py"

    def test_resolve_import_package(self, tmp_path: Path) -> None:
        """resolve_import finds a package __init__.py."""
        pkg = tmp_path / "mypkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        base = tmp_path / "main.py"
        base.write_text("", encoding="utf-8")
        tracker = DependencyTracker()
        result = tracker.resolve_import("mypkg", base)
        assert result is not None

    def test_resolve_import_not_found(self, tmp_path: Path) -> None:
        """resolve_import returns None for missing imports."""
        base = tmp_path / "main.py"
        base.write_text("", encoding="utf-8")
        tracker = DependencyTracker()
        assert tracker.resolve_import("nonexistent", base) is None

    def test_build_dependency_graph(self, tmp_path: Path) -> None:
        """build_dependency_graph creates a graph dict."""
        (tmp_path / "a.py").write_text("import os\n", encoding="utf-8")
        tracker = DependencyTracker()
        graph = tracker.build_dependency_graph([tmp_path / "a.py"])
        assert isinstance(graph, dict)
        assert str(tmp_path / "a.py") in graph
