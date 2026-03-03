"""Tests for watch mode and incremental analysis."""

import importlib.util

import pytest

import sys

import time

import tempfile

import types

from pathlib import Path

from types import SimpleNamespace

from unittest.mock import Mock, patch


from pysymex.watch import (
    FileEventType,
    FileEvent,
    FileState,
    FileWatcher,
    AnalysisCache,
    IncrementalAnalyzer,
    WatchModeRunner,
    DependencyTracker,
)


class TestFileEvent:
    """Tests for FileEvent."""

    def test_create_event(self):
        """Test creating a file event."""

        event = FileEvent(
            path=Path("test.py"),
            event_type=FileEventType.MODIFIED,
        )

        assert event.path == Path("test.py")

        assert event.event_type == FileEventType.MODIFIED

        assert event.timestamp > 0

    def test_created_event(self):
        """Test created event type."""

        event = FileEvent(
            path=Path("new.py"),
            event_type=FileEventType.CREATED,
        )

        assert event.event_type == FileEventType.CREATED

    def test_deleted_event(self):
        """Test deleted event type."""

        event = FileEvent(
            path=Path("old.py"),
            event_type=FileEventType.DELETED,
        )

        assert event.event_type == FileEventType.DELETED

    def test_renamed_event(self):
        """Test renamed event with old path."""

        event = FileEvent(
            path=Path("new_name.py"),
            event_type=FileEventType.RENAMED,
            old_path=Path("old_name.py"),
        )

        assert event.event_type == FileEventType.RENAMED

        assert event.old_path == Path("old_name.py")


class TestFileState:
    """Tests for FileState."""

    def test_from_path(self, tmp_path):
        """Test creating state from file path."""

        test_file = tmp_path / "test.py"

        test_file.write_text("print('hello')")

        state = FileState.from_path(test_file)

        assert state.path == test_file

        assert state.size > 0

        assert len(state.content_hash) == 64

    def test_has_changed(self, tmp_path):
        """Test detecting file changes."""

        test_file = tmp_path / "test.py"

        test_file.write_text("version 1")

        state1 = FileState.from_path(test_file)

        test_file.write_text("version 2")

        state2 = FileState.from_path(test_file)

        assert state1.has_changed(state2)

    def test_no_change(self, tmp_path):
        """Test detecting no change."""

        test_file = tmp_path / "test.py"

        test_file.write_text("same content")

        state1 = FileState.from_path(test_file)

        state2 = FileState.from_path(test_file)

        assert not state1.has_changed(state2)


class TestFileWatcher:
    """Tests for FileWatcher."""

    def test_create_watcher(self, tmp_path):
        """Test creating a file watcher."""

        watcher = FileWatcher(
            paths=[tmp_path],
            patterns=["*.py"],
            poll_interval=0.1,
        )

        assert tmp_path in watcher.paths

        assert "*.py" in watcher.patterns

    def test_on_change_callback(self, tmp_path):
        """Test registering change callback."""

        watcher = FileWatcher(paths=[tmp_path])

        events = []

        watcher.on_change(lambda e: events.append(e))

        assert len(watcher._callbacks) == 1

    def test_get_matching_files(self, tmp_path):
        """Test getting matching files."""

        (tmp_path / "a.py").write_text("a")

        (tmp_path / "b.py").write_text("b")

        (tmp_path / "c.txt").write_text("c")

        watcher = FileWatcher(paths=[tmp_path], patterns=["*.py"])

        files = watcher._get_matching_files()

        assert len(files) == 2

        names = {f.name for f in files}

        assert "a.py" in names

        assert "b.py" in names

        assert "c.txt" not in names

    def test_check_changes_new_file(self, tmp_path):
        """Test detecting new file."""

        watcher = FileWatcher(paths=[tmp_path])

        watcher._scan_initial()

        (tmp_path / "new.py").write_text("new")

        events = watcher._check_changes()

        assert len(events) == 1

        assert events[0].event_type == FileEventType.CREATED

    def test_check_changes_modified(self, tmp_path):
        """Test detecting modified file."""

        test_file = tmp_path / "test.py"

        test_file.write_text("original")

        watcher = FileWatcher(paths=[tmp_path])

        watcher._scan_initial()

        test_file.write_text("modified")

        events = watcher._check_changes()

        assert len(events) == 1

        assert events[0].event_type == FileEventType.MODIFIED

    def test_check_changes_deleted(self, tmp_path):
        """Test detecting deleted file."""

        test_file = tmp_path / "test.py"

        test_file.write_text("content")

        watcher = FileWatcher(paths=[tmp_path])

        watcher._scan_initial()

        test_file.unlink()

        events = watcher._check_changes()

        assert len(events) == 1

        assert events[0].event_type == FileEventType.DELETED


class TestAnalysisCache:
    """Tests for AnalysisCache."""

    def test_create_cache(self):
        """Test creating analysis cache."""

        cache = AnalysisCache(
            file_hash="abc123",
            timestamp=time.time(),
            result={"issues": []},
        )

        assert cache.file_hash == "abc123"

        assert cache.result == {"issues": []}

    def test_is_valid_same_hash(self):
        """Test cache validity with same hash."""

        cache = AnalysisCache(
            file_hash="hash123",
            timestamp=time.time(),
            result={},
        )

        assert cache.is_valid("hash123")

    def test_is_valid_different_hash(self):
        """Test cache invalidity with different hash."""

        cache = AnalysisCache(
            file_hash="hash123",
            timestamp=time.time(),
            result={},
        )

        assert not cache.is_valid("different")


class TestIncrementalAnalyzer:
    """Tests for IncrementalAnalyzer."""

    def test_add_dependency(self):
        """Test adding file dependency."""

        analyzer = IncrementalAnalyzer()

        analyzer.add_dependency("a.py", "b.py")

        assert "b.py" in analyzer._dependencies.get("a.py", set())

        assert "a.py" in analyzer._dependents.get("b.py", set())

    def test_get_affected_files(self):
        """Test getting affected files."""

        analyzer = IncrementalAnalyzer()

        analyzer.add_dependency("a.py", "b.py")

        analyzer.add_dependency("c.py", "a.py")

        affected = analyzer.get_affected_files("b.py")

        assert "b.py" in affected

        assert "a.py" in affected

        assert "c.py" in affected

    def test_cache_result(self, tmp_path):
        """Test caching analysis result."""

        test_file = tmp_path / "test.py"

        test_file.write_text("code")

        analyzer = IncrementalAnalyzer()

        analyzer.cache_result(str(test_file), {"status": "ok"})

        cached = analyzer.get_cached(str(test_file))

        assert cached is not None

        assert cached.result == {"status": "ok"}

    def test_get_cached_invalid(self, tmp_path):
        """Test getting invalidated cache."""

        test_file = tmp_path / "test.py"

        test_file.write_text("version1")

        analyzer = IncrementalAnalyzer()

        analyzer.cache_result(str(test_file), {"v": 1})

        test_file.write_text("version2")

        cached = analyzer.get_cached(str(test_file))

        assert cached is None

    def test_invalidate(self, tmp_path):
        """Test invalidating cache."""

        test_file = tmp_path / "test.py"

        test_file.write_text("code")

        analyzer = IncrementalAnalyzer()

        analyzer.cache_result(str(test_file), {"result": 1})

        analyzer.invalidate(str(test_file))

        assert str(test_file) not in analyzer._cache

    def test_clear_cache(self, tmp_path):
        """Test clearing all cache."""

        analyzer = IncrementalAnalyzer()

        for i in range(5):
            f = tmp_path / f"test{i}.py"

            f.write_text(f"code{i}")

            analyzer.cache_result(str(f), {"i": i})

        analyzer.clear_cache()

        assert len(analyzer._cache) == 0


class TestDependencyTracker:
    """Tests for DependencyTracker."""

    def test_extract_imports(self, tmp_path):
        """Test extracting imports from file."""

        test_file = tmp_path / "test.py"

        test_file.write_text("""
import os
from pathlib import Path
import json
from . import local
""")

        tracker = DependencyTracker()

        imports = tracker.extract_imports(test_file)

        assert "os" in imports

        assert "pathlib" in imports

        assert "json" in imports

    def test_resolve_import_relative(self, tmp_path):
        """Test resolving relative import."""

        module_file = tmp_path / "mymodule.py"

        module_file.write_text("# module")

        main_file = tmp_path / "main.py"

        main_file.write_text("import mymodule")

        tracker = DependencyTracker()

        resolved = tracker.resolve_import("mymodule", main_file)

        assert resolved == module_file

    def test_resolve_import_package(self, tmp_path):
        """Test resolving package import."""

        pkg_dir = tmp_path / "mypackage"

        pkg_dir.mkdir()

        init_file = pkg_dir / "__init__.py"

        init_file.write_text("# init")

        main_file = tmp_path / "main.py"

        tracker = DependencyTracker()

        resolved = tracker.resolve_import("mypackage", main_file)

        assert resolved == init_file

    def test_build_dependency_graph(self, tmp_path):
        """Test building dependency graph."""

        (tmp_path / "base.py").write_text("# base module")

        (tmp_path / "derived.py").write_text("import base")

        (tmp_path / "main.py").write_text("import derived")

        tracker = DependencyTracker()

        graph = tracker.build_dependency_graph(
            [
                tmp_path / "base.py",
                tmp_path / "derived.py",
                tmp_path / "main.py",
            ]
        )

        assert len(graph) == 3


class TestWatchModeRunner:
    """Tests for WatchModeRunner."""

    def test_create_runner(self, tmp_path):
        """Test creating watch mode runner."""

        runner = WatchModeRunner(paths=[tmp_path])

        assert tmp_path in runner.paths

        assert runner.watcher is not None

        assert runner.analyzer is not None

    def test_on_result_callback(self, tmp_path):
        """Test result callback."""

        results = []

        runner = WatchModeRunner(
            paths=[tmp_path],
            on_result=lambda f, r: results.append((f, r)),
        )

        test_file = tmp_path / "test.py"

        test_file.write_text("print(1)")

        runner._analyze_file(test_file)

        assert len(results) == 1

    def test_on_error_callback(self, tmp_path):
        """Test error callback."""

        errors = []

        runner = WatchModeRunner(
            paths=[tmp_path],
            on_error=lambda f, e: errors.append((f, e)),
        )

        assert runner.on_error is not None

    def test_cached_analysis(self, tmp_path):
        """Test cached analysis is used."""

        test_file = tmp_path / "test.py"

        test_file.write_text("x = 1")

        runner = WatchModeRunner(paths=[tmp_path])

        runner._analyze_file(test_file)

        runner._analyze_file(test_file)

        cached = runner.analyzer.get_cached(str(test_file))

        assert cached is not None


class TestCLIIncrementalWatch:
    """Tests for CLI watch mode incremental behavior."""

    @staticmethod
    def _load_cli_module():
        module_name = "pysymex_cli_watch_test"

        if module_name in sys.modules:
            del sys.modules[module_name]

        cli_path = Path(__file__).resolve().parents[1] / "pysymex" / "cli" / "__init__.py"

        spec = importlib.util.spec_from_file_location(module_name, cli_path)

        assert spec and spec.loader

        module = importlib.util.module_from_spec(spec)

        spec.loader.exec_module(module)

        return module

    def test_watch_mode_rescans_only_changed_files(self, monkeypatch, tmp_path):
        cli = self._load_cli_module()

        file_a = tmp_path / "a.py"

        file_b = tmp_path / "b.py"

        file_a.write_text("x = 1\n", encoding="utf-8")

        file_b.write_text("y = 1\n", encoding="utf-8")

        scanned: list[str] = []

        fake_api = types.ModuleType("pysymex.api")

        def fake_scan_static(
            path, recursive=False, verbose=False, min_confidence=0.7, show_suppressed=False
        ):
            scanned.append(Path(path).name)

            return []

        fake_api.scan_static = fake_scan_static

        monkeypatch.setitem(sys.modules, "pysymex.api", fake_api)

        fake_watch = types.ModuleType("pysymex.watch")

        class FakeCacheEntry:
            def __init__(self, result):
                self.result = result

        class FakeIncrementalAnalyzer:
            def __init__(self, engine=None):
                self._cache = {}

            def get_cached(self, file):
                result = self._cache.get(file)

                return FakeCacheEntry(result) if result is not None else None

            def cache_result(self, file, result, dependencies=None):
                self._cache[file] = result

            def invalidate(self, file):
                self._cache.pop(file, None)

                return {file}

        fake_watch.IncrementalAnalyzer = FakeIncrementalAnalyzer

        monkeypatch.setitem(sys.modules, "pysymex.watch", fake_watch)

        sleep_calls = {"count": 0}

        def fake_sleep(_seconds):
            sleep_calls["count"] += 1

            if sleep_calls["count"] == 1:
                file_a.write_text("x = 2\n", encoding="utf-8")

                return

            raise KeyboardInterrupt

        monkeypatch.setattr(cli.time, "sleep", fake_sleep)

        args = SimpleNamespace(
            path=str(tmp_path),
            recursive=True,
            mode="static",
            verbose=False,
            max_paths=1000,
            timeout=60.0,
            auto=False,
            format="text",
            output=None,
            reproduce=False,
        )

        exit_code = cli.cmd_scan_watch(args)

        assert exit_code == 0

        assert scanned.count("a.py") == 2

        assert scanned.count("b.py") == 1
