# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Watch mode and incremental analysis for pysymex.
Provides file watching, incremental analysis, and caching for
efficient re-analysis during development.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import (
    TYPE_CHECKING,
)

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from pysymex.execution.executors import SymbolicExecutor as SymbolicEngine


class FileEventType(Enum):
    """Types of file system events."""

    CREATED = auto()
    MODIFIED = auto()
    DELETED = auto()
    RENAMED = auto()


@dataclass(frozen=True, slots=True)
class FileEvent:
    """A file system event."""

    path: Path
    event_type: FileEventType
    timestamp: float = field(default_factory=time.time)
    old_path: Path | None = None


@dataclass(frozen=True, slots=True)
class FileState:
    """Tracked state of a file."""

    path: Path
    mtime: float
    size: int
    content_hash: str

    @classmethod
    def from_path(cls, path: Path) -> FileState:
        """Create state from file path."""
        stat = path.stat()
        content = path.read_bytes()
        content_hash = hashlib.sha256(content).hexdigest()
        return cls(
            path=path,
            mtime=stat.st_mtime,
            size=stat.st_size,
            content_hash=content_hash,
        )

    def has_changed(self, other: FileState) -> bool:
        """Check if file has changed."""
        return self.content_hash != other.content_hash


class FileWatcher:
    """Watches files for changes.
    A simple polling-based file watcher that doesn't require
    platform-specific dependencies like watchdog.
    """

    def __init__(
        self,
        paths: list[Path],
        patterns: list[str] | None = None,
        poll_interval: float = 0.5,
    ) -> None:
        self.paths = paths
        self.patterns = patterns or ["*.py"]
        self.poll_interval = poll_interval
        self._states: dict[Path, FileState] = {}
        self._callbacks: list[Callable[[FileEvent], None]] = []
        self._running = False
        self._thread: threading.Thread | None = None

    def on_change(self, callback: Callable[[FileEvent], None]) -> None:
        """Register a callback for file changes."""
        self._callbacks.append(callback)

    def start(self) -> None:
        """Start watching for changes."""
        self._running = True
        self._scan_initial()
        self._thread = threading.Thread(target=self._watch_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop watching."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=1.0)

    def _get_matching_files(self) -> set[Path]:
        """Get all files matching patterns."""
        files: set[Path] = set()
        for base_path in self.paths:
            if base_path.is_file():
                files.add(base_path)
            elif base_path.is_dir():
                for pattern in self.patterns:
                    files.update(base_path.rglob(pattern))
        return files

    def _scan_initial(self) -> None:
        """Initial scan of all files."""
        for path in self._get_matching_files():
            try:
                self._states[path] = FileState.from_path(path)
            except OSError:
                pass

    def _watch_loop(self) -> None:
        """Main watch loop."""
        while self._running:
            events = self._check_changes()
            for event in events:
                for callback in self._callbacks:
                    try:
                        callback(event)
                    except Exception:
                        logger.warning(
                            "Error in file watcher callback",
                            exc_info=True,
                        )
            time.sleep(self.poll_interval)

    def _check_changes(self) -> list[FileEvent]:
        """Check for file changes."""
        events: list[FileEvent] = []
        current_files = self._get_matching_files()
        for path in current_files:
            try:
                new_state = FileState.from_path(path)
                if path not in self._states:
                    events.append(
                        FileEvent(
                            path=path,
                            event_type=FileEventType.CREATED,
                        )
                    )
                elif new_state.has_changed(self._states[path]):
                    events.append(
                        FileEvent(
                            path=path,
                            event_type=FileEventType.MODIFIED,
                        )
                    )
                self._states[path] = new_state
            except OSError:
                pass
        for path in list(self._states.keys()):
            if path not in current_files:
                events.append(
                    FileEvent(
                        path=path,
                        event_type=FileEventType.DELETED,
                    )
                )
                del self._states[path]
        return events


class AsyncFileWatcher:
    """Async version of :class:`FileWatcher` using ``asyncio``.

    Uses an :class:`asyncio.Event` to signal shutdown and
    ``asyncio.sleep`` instead of blocking ``time.sleep``.

    Example::

        watcher = AsyncFileWatcher([Path("src/")])
        watcher.on_change(my_callback)
        await watcher.start()   # runs until cancelled
    """

    def __init__(
        self,
        paths: list[Path],
        patterns: list[str] | None = None,
        poll_interval: float = 0.5,
    ) -> None:
        self.paths = paths
        self.patterns = patterns or ["*.py"]
        self.poll_interval = poll_interval
        self._states: dict[Path, FileState] = {}
        self._callbacks: list[Callable[[FileEvent], object]] = []
        self._stop_event = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    def on_change(self, callback: Callable[[FileEvent], object]) -> None:
        """Register a callback for file changes (sync or async)."""
        self._callbacks.append(callback)

    async def start(self) -> None:
        """Start watching for changes in the background."""
        self._stop_event.clear()
        self._scan_initial()
        self._task = asyncio.create_task(self._watch_loop())

    async def stop(self) -> None:
        """Stop watching and await the background task."""
        self._stop_event.set()
        if self._task is not None:
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    def _get_matching_files(self) -> set[Path]:
        """Get all files matching patterns."""
        files: set[Path] = set()
        for base_path in self.paths:
            if base_path.is_file():
                files.add(base_path)
            elif base_path.is_dir():
                for pattern in self.patterns:
                    files.update(base_path.rglob(pattern))
        return files

    def _scan_initial(self) -> None:
        """Initial scan of all files."""
        for path in self._get_matching_files():
            try:
                self._states[path] = FileState.from_path(path)
            except OSError:
                pass

    async def _watch_loop(self) -> None:
        """Async main watch loop."""
        while not self._stop_event.is_set():
            events = self._check_changes()
            for event in events:
                for callback in self._callbacks:
                    try:
                        result = callback(event)
                        if asyncio.iscoroutine(result):
                            await result
                    except Exception:
                        logger.warning(
                            "Error in async file watcher callback",
                            exc_info=True,
                        )
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self.poll_interval,
                )
                break
            except TimeoutError:
                continue

    def _check_changes(self) -> list[FileEvent]:
        """Check for file changes."""
        events: list[FileEvent] = []
        current_files = self._get_matching_files()
        for path in current_files:
            try:
                new_state = FileState.from_path(path)
                if path not in self._states:
                    events.append(
                        FileEvent(
                            path=path,
                            event_type=FileEventType.CREATED,
                        )
                    )
                elif new_state.has_changed(self._states[path]):
                    events.append(
                        FileEvent(
                            path=path,
                            event_type=FileEventType.MODIFIED,
                        )
                    )
                self._states[path] = new_state
            except OSError:
                pass
        for path in list(self._states.keys()):
            if path not in current_files:
                events.append(
                    FileEvent(
                        path=path,
                        event_type=FileEventType.DELETED,
                    )
                )
                del self._states[path]
        return events


@dataclass
class AnalysisCache:
    """Cache for analysis results."""

    file_hash: str
    timestamp: float
    result: object
    dependencies: set[str] = field(default_factory=lambda: set[str]())

    def is_valid(self, current_hash: str) -> bool:
        """Check if cache is still valid."""
        return self.file_hash == current_hash


class IncrementalAnalyzer:
    """Provides incremental analysis with caching.
    Only re-analyzes files that have changed since the last analysis,
    taking into account dependencies between files.
    """

    def __init__(self, engine: SymbolicEngine | None = None) -> None:
        self.engine = engine
        self._cache: dict[str, AnalysisCache] = {}
        self._dependencies: dict[str, set[str]] = {}
        self._dependents: dict[str, set[str]] = {}

    def add_dependency(self, file: str, depends_on: str) -> None:
        """Record that file depends on another file."""
        if file not in self._dependencies:
            self._dependencies[file] = set()
        self._dependencies[file].add(depends_on)
        if depends_on not in self._dependents:
            self._dependents[depends_on] = set()
        self._dependents[depends_on].add(file)

    def get_affected_files(self, changed_file: str) -> set[str]:
        """Get all files affected by a change."""
        affected = {changed_file}
        to_check = [changed_file]
        while to_check:
            current = to_check.pop()
            for dependent in self._dependents.get(current, []):
                if dependent not in affected:
                    affected.add(dependent)
                    to_check.append(dependent)
        return affected

    def get_cached(self, file: str) -> AnalysisCache | None:
        """Get cached analysis result."""
        if file not in self._cache:
            return None
        try:
            path = Path(file)
            current_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            cache = self._cache[file]
            if cache.is_valid(current_hash):
                for dep in cache.dependencies:
                    dep_cache = self._cache.get(dep)
                    if not dep_cache:
                        return None
                    dep_path = Path(dep)
                    if dep_path.exists():
                        dep_hash = hashlib.sha256(dep_path.read_bytes()).hexdigest()
                        if not dep_cache.is_valid(dep_hash):
                            return None
                return cache
        except OSError:
            pass
        return None

    def cache_result(
        self,
        file: str,
        result: object,
        dependencies: set[str] | None = None,
    ) -> None:
        """Cache an analysis result."""
        try:
            path = Path(file)
            file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            self._cache[file] = AnalysisCache(
                file_hash=file_hash,
                timestamp=time.time(),
                result=result,
                dependencies=dependencies or set(),
            )
        except OSError:
            pass

    def invalidate(self, file: str) -> set[str]:
        """Invalidate cache for a file and its dependents."""
        invalidated = self.get_affected_files(file)
        for f in invalidated:
            self._cache.pop(f, None)
        return invalidated

    def clear_cache(self) -> None:
        """Clear all cached results."""
        self._cache.clear()


class WatchModeRunner:
    """Runs symbolic analysis in watch mode.
    Watches for file changes and automatically re-runs analysis,
    using incremental analysis to minimize work.
    """

    def __init__(
        self,
        paths: list[Path],
        engine: SymbolicEngine | None = None,
        on_result: Callable[[str, object], None] | None = None,
        on_error: Callable[[str, Exception], None] | None = None,
    ) -> None:
        self.paths = paths
        self.engine = engine
        self.on_result = on_result
        self.on_error = on_error
        self.watcher = FileWatcher(paths)
        self.analyzer = IncrementalAnalyzer(engine)
        self._running = False

    def start(self) -> None:
        """Start watch mode."""
        self._running = True
        print("ðŸ‘€ PySyMex Watch Mode")
        print(f"   Watching: {', '.join(str(p) for p in self.paths)}")
        print("   Press Ctrl+C to stop\n")
        self._analyze_all()
        self.watcher.on_change(self._handle_change)
        self.watcher.start()
        try:
            while self._running:
                time.sleep(0.1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self) -> None:
        """Stop watch mode."""
        self._running = False
        self.watcher.stop()
        print("\nðŸ‘‹ Watch mode stopped")

    def _analyze_all(self) -> None:
        """Analyze all watched files."""
        for path in self.paths:
            if path.is_file():
                self._analyze_file(path)
            elif path.is_dir():
                for py_file in path.rglob("*.py"):
                    self._analyze_file(py_file)

    def _analyze_file(self, path: Path) -> None:
        """Analyze a single file."""
        file_str = str(path)
        cached = self.analyzer.get_cached(file_str)
        if cached:
            print(f"ðŸ“¦ Using cached: {path.name}")
            if self.on_result:
                self.on_result(file_str, cached.result)
            return
        try:
            print(f"ðŸ” Analyzing: {path.name}")
            if self.engine:
                result = self._run_analysis(path)
            else:
                result = {"status": "no_engine"}
            self.analyzer.cache_result(file_str, result)
            if self.on_result:
                self.on_result(file_str, result)
        except Exception as e:
            print(f"âŒ Error analyzing {path.name}: {e}")
            if self.on_error:
                self.on_error(file_str, e)

    def _run_analysis(self, path: Path) -> object:
        """Run analysis on a file."""
        return {"status": "analyzed", "file": str(path)}

    def _handle_change(self, event: FileEvent) -> None:
        """Handle a file change event."""
        if event.event_type == FileEventType.DELETED:
            print(f"ðŸ—‘ï¸  Deleted: {event.path.name}")
            self.analyzer.invalidate(str(event.path))
            return
        print(
            f"\n{'âœ¨' if event.event_type == FileEventType.CREATED else 'ðŸ“'} "
            f"{'Created' if event.event_type == FileEventType.CREATED else 'Modified'}: "
            f"{event.path.name}"
        )
        affected = self.analyzer.invalidate(str(event.path))
        for file_str in affected:
            path = Path(file_str)
            if path.exists():
                self._analyze_file(path)


class DependencyTracker:
    """Tracks import dependencies between Python files."""

    def __init__(self) -> None:
        self._imports: dict[str, set[str]] = {}

    def extract_imports(self, path: Path) -> set[str]:
        """Extract imports from a Python file."""
        imports: set[str] = set()
        try:
            import ast

            content = path.read_text()
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module.split(".")[0])
        except (OSError, SyntaxError):
            pass
        return imports

    def resolve_import(self, import_name: str, base_path: Path) -> Path | None:
        """Try to resolve an import to a file path."""
        relative = base_path.parent / f"{import_name}.py"
        if relative.exists():
            return relative
        package_init = base_path.parent / import_name / "__init__.py"
        if package_init.exists():
            return package_init
        return None

    def build_dependency_graph(
        self,
        paths: list[Path],
    ) -> dict[str, set[str]]:
        """Build dependency graph for files."""
        graph: dict[str, set[str]] = {}
        for path in paths:
            if path.is_file() and path.suffix == ".py":
                imports = self.extract_imports(path)
                deps: set[str] = set()
                for imp in imports:
                    resolved = self.resolve_import(imp, path)
                    if resolved:
                        deps.add(str(resolved))
                graph[str(path)] = deps
        return graph


__all__ = [
    "AnalysisCache",
    "AsyncFileWatcher",
    "DependencyTracker",
    "FileEvent",
    "FileEventType",
    "FileState",
    "FileWatcher",
    "IncrementalAnalyzer",
    "WatchModeRunner",
]


