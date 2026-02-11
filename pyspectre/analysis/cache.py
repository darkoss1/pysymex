"""Persistent caching and parallel analysis for PySpectre.
Provides SQLite-backed caching, LRU memory cache, smart invalidation,
and parallel analysis capabilities for efficient large-scale analysis.
"""

from __future__ import annotations
import hashlib
import json
import os
import pickle
import sqlite3
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import (
    Any,
    Generic,
    TypeVar,
)

T = TypeVar("T")
K = TypeVar("K")
V = TypeVar("V")


class CacheKeyType(Enum):
    """Types of cache keys."""

    FUNCTION = auto()
    BYTECODE = auto()
    MODULE = auto()
    SUMMARY = auto()
    VERIFICATION = auto()
    CUSTOM = auto()


@dataclass(frozen=True)
class CacheKey:
    """Immutable cache key."""

    key_type: CacheKeyType
    identifier: str
    version: str = "1.0"

    def __hash__(self) -> int:
        return hash((self.key_type, self.identifier, self.version))

    def to_string(self) -> str:
        """Convert to string representation."""
        return f"{self.key_type.name}:{self.identifier}:{self.version}"

    @classmethod
    def from_string(cls, s: str) -> CacheKey:
        """Parse from string representation."""
        parts = s.split(":", 2)
        if len(parts) != 3:
            raise ValueError(f"Invalid cache key string: {s}")
        return cls(
            key_type=CacheKeyType[parts[0]],
            identifier=parts[1],
            version=parts[2],
        )


def hash_bytecode(code: bytes) -> str:
    """Hash bytecode for caching."""
    return hashlib.sha256(code).hexdigest()


def hash_function(func_name: str, code: bytes, signature: str = "") -> str:
    """Hash a function for caching."""
    content = f"{func_name}:{signature}:".encode() + code
    return hashlib.sha256(content).hexdigest()


def hash_file(path: Path) -> str:
    """Hash a file for caching."""
    content = path.read_bytes()
    return hashlib.sha256(content).hexdigest()


def hash_dict(d: dict[str, Any]) -> str:
    """Hash a dictionary for caching."""
    content = json.dumps(d, sort_keys=True, default=str)
    return hashlib.sha256(content.encode()).hexdigest()


class LRUCache(Generic[K, V]):
    """Thread-safe LRU cache with size limit.
    Keeps most recently used items in memory up to a maximum size.
    """

    def __init__(self, maxsize: int = 1000):
        self.maxsize = maxsize
        self._cache: OrderedDict[K, V] = OrderedDict()
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0

    def get(self, key: K, default: V = None) -> V | None:
        """Get item from cache."""
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                self._hits += 1
                return self._cache[key]
            self._misses += 1
            return default

    def put(self, key: K, value: V) -> None:
        """Put item in cache."""
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = value
            while len(self._cache) > self.maxsize:
                self._cache.popitem(last=False)

    def remove(self, key: K) -> bool:
        """Remove item from cache."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    def clear(self) -> None:
        """Clear all items."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0

    def __contains__(self, key: K) -> bool:
        with self._lock:
            return key in self._cache

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)

    @property
    def hit_rate(self) -> float:
        """Get cache hit rate."""
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    def stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            return {
                "size": len(self._cache),
                "maxsize": self.maxsize,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": self.hit_rate,
            }


@dataclass
class CacheEntry:
    """Entry in persistent cache."""

    key: str
    key_type: str
    value_hash: str
    value_blob: bytes
    created_at: float
    accessed_at: float
    access_count: int
    dependencies: str

    @property
    def age(self) -> float:
        """Get age in seconds."""
        return time.time() - self.created_at


class PersistentCache:
    """SQLite-backed persistent cache.
    Provides durable storage of analysis results with automatic
    cleanup and dependency tracking.
    """

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS cache (
        key TEXT PRIMARY KEY,
        key_type TEXT NOT NULL,
        value_hash TEXT NOT NULL,
        value_blob BLOB NOT NULL,
        created_at REAL NOT NULL,
        accessed_at REAL NOT NULL,
        access_count INTEGER DEFAULT 1,
        dependencies TEXT DEFAULT '[]'
    );
    CREATE INDEX IF NOT EXISTS idx_key_type ON cache(key_type);
    CREATE INDEX IF NOT EXISTS idx_created_at ON cache(created_at);
    CREATE INDEX IF NOT EXISTS idx_accessed_at ON cache(accessed_at);
    """

    def __init__(
        self,
        db_path: Path | None = None,
        max_entries: int = 10000,
        max_age_days: int = 30,
    ):
        self.db_path = db_path or Path.home() / ".pyspectre" / "cache.db"
        self.max_entries = max_entries
        self.max_age_days = max_age_days
        self._ensure_directory()
        self._init_database()

    def _ensure_directory(self) -> None:
        """Ensure cache directory exists."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _init_database(self) -> None:
        """Initialize database schema."""
        with self._connect() as conn:
            conn.executescript(self.SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        """Create database connection."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def get(self, key: CacheKey) -> Any | None:
        """Get value from cache."""
        key_str = key.to_string()
        with self._connect() as conn:
            cursor = conn.execute("SELECT * FROM cache WHERE key = ?", (key_str,))
            row = cursor.fetchone()
            if row:
                conn.execute(
                    """
                    UPDATE cache 
                    SET accessed_at = ?, access_count = access_count + 1
                    WHERE key = ?
                    """,
                    (time.time(), key_str),
                )
                try:
                    return pickle.loads(row["value_blob"])
                except Exception:
                    return None
        return None

    def put(
        self,
        key: CacheKey,
        value: Any,
        dependencies: list[CacheKey] | None = None,
    ) -> bool:
        """Put value in cache."""
        key_str = key.to_string()
        try:
            value_blob = pickle.dumps(value)
            value_hash = hashlib.sha256(value_blob).hexdigest()
            dep_json = json.dumps([d.to_string() for d in (dependencies or [])])
            now = time.time()
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO cache 
                    (key, key_type, value_hash, value_blob, created_at, 
                     accessed_at, access_count, dependencies)
                    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                    """,
                    (key_str, key.key_type.name, value_hash, value_blob, now, now, dep_json),
                )
            return True
        except Exception:
            return False

    def remove(self, key: CacheKey) -> bool:
        """Remove entry from cache."""
        key_str = key.to_string()
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM cache WHERE key = ?", (key_str,))
            return cursor.rowcount > 0

    def invalidate_by_type(self, key_type: CacheKeyType) -> int:
        """Invalidate all entries of a type."""
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM cache WHERE key_type = ?", (key_type.name,))
            return cursor.rowcount

    def invalidate_dependencies(self, key: CacheKey) -> set[str]:
        """Invalidate all entries that depend on a key."""
        key_str = key.to_string()
        invalidated = set()
        with self._connect() as conn:
            cursor = conn.execute("SELECT key, dependencies FROM cache")
            for row in cursor:
                deps = json.loads(row["dependencies"])
                if key_str in deps:
                    invalidated.add(row["key"])
            if invalidated:
                placeholders = ",".join("?" * len(invalidated))
                conn.execute(f"DELETE FROM cache WHERE key IN ({placeholders})", tuple(invalidated))
        return invalidated

    def clear(self) -> int:
        """Clear all entries."""
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM cache")
            return cursor.rowcount

    def cleanup(self) -> int:
        """Clean up old and excess entries."""
        removed = 0
        now = time.time()
        max_age_seconds = self.max_age_days * 24 * 60 * 60
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM cache WHERE created_at < ?", (now - max_age_seconds,)
            )
            removed += cursor.rowcount
            cursor = conn.execute("SELECT COUNT(*) FROM cache")
            count = cursor.fetchone()[0]
            if count > self.max_entries:
                excess = count - self.max_entries
                conn.execute(
                    """
                    DELETE FROM cache WHERE key IN (
                        SELECT key FROM cache 
                        ORDER BY accessed_at ASC 
                        LIMIT ?
                    )
                    """,
                    (excess,),
                )
                removed += excess
        return removed

    def stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        with self._connect() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM cache")
            count = cursor.fetchone()[0]
            cursor = conn.execute("SELECT key_type, COUNT(*) as cnt FROM cache GROUP BY key_type")
            by_type = {row["key_type"]: row["cnt"] for row in cursor}
            cursor = conn.execute("SELECT SUM(access_count) as total FROM cache")
            total_accesses = cursor.fetchone()["total"] or 0
            return {
                "db_path": str(self.db_path),
                "entry_count": count,
                "by_type": by_type,
                "total_accesses": total_accesses,
                "max_entries": self.max_entries,
            }

    def __contains__(self, key: CacheKey) -> bool:
        key_str = key.to_string()
        with self._connect() as conn:
            cursor = conn.execute("SELECT 1 FROM cache WHERE key = ?", (key_str,))
            return cursor.fetchone() is not None

    def __len__(self) -> int:
        with self._connect() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM cache")
            return cursor.fetchone()[0]


class TieredCache:
    """Two-level cache with memory and persistent storage.
    Uses LRU cache for fast access and SQLite for persistence.
    """

    def __init__(
        self,
        memory_size: int = 1000,
        db_path: Path | None = None,
    ):
        self.memory = LRUCache[str, Any](maxsize=memory_size)
        self.persistent = PersistentCache(db_path=db_path)

    def get(self, key: CacheKey) -> Any | None:
        """Get from cache, checking memory first."""
        key_str = key.to_string()
        value = self.memory.get(key_str)
        if value is not None:
            return value
        value = self.persistent.get(key)
        if value is not None:
            self.memory.put(key_str, value)
            return value
        return None

    def put(
        self,
        key: CacheKey,
        value: Any,
        persist: bool = True,
        dependencies: list[CacheKey] | None = None,
    ) -> None:
        """Put in cache."""
        key_str = key.to_string()
        self.memory.put(key_str, value)
        if persist:
            self.persistent.put(key, value, dependencies)

    def remove(self, key: CacheKey) -> bool:
        """Remove from both caches."""
        key_str = key.to_string()
        mem_removed = self.memory.remove(key_str)
        pers_removed = self.persistent.remove(key)
        return mem_removed or pers_removed

    def clear(self) -> None:
        """Clear both caches."""
        self.memory.clear()
        self.persistent.clear()

    def stats(self) -> dict[str, Any]:
        """Get combined statistics."""
        return {
            "memory": self.memory.stats(),
            "persistent": self.persistent.stats(),
        }


@dataclass
class AnalysisTask:
    """A task for parallel analysis."""

    task_id: str
    target: Any
    priority: int = 0
    dependencies: list[str] = field(default_factory=list)

    def __lt__(self, other: AnalysisTask) -> bool:
        return self.priority > other.priority


@dataclass
class AnalysisResult:
    """Result of an analysis task."""

    task_id: str
    success: bool
    result: Any = None
    error: str | None = None
    duration: float = 0.0


class ProgressReporter:
    """Reports progress of parallel analysis."""

    def __init__(self):
        self.total = 0
        self.completed = 0
        self.failed = 0
        self._lock = threading.Lock()
        self._callbacks: list[Callable[[int, int, int], None]] = []

    def set_total(self, total: int) -> None:
        """Set total number of tasks."""
        with self._lock:
            self.total = total
            self.completed = 0
            self.failed = 0

    def report_complete(self, success: bool = True) -> None:
        """Report task completion."""
        with self._lock:
            self.completed += 1
            if not success:
                self.failed += 1
            for callback in self._callbacks:
                try:
                    callback(self.completed, self.total, self.failed)
                except Exception:
                    pass

    def on_progress(self, callback: Callable[[int, int, int], None]) -> None:
        """Register progress callback."""
        self._callbacks.append(callback)

    @property
    def progress(self) -> float:
        """Get progress as fraction."""
        with self._lock:
            return self.completed / self.total if self.total > 0 else 0.0

    def format_progress(self) -> str:
        """Format progress for display."""
        with self._lock:
            pct = (self.completed / self.total * 100) if self.total > 0 else 0.0
            return f"[{self.completed}/{self.total}] {pct:.1f}% ({self.failed} failed)"


class ParallelAnalyzer:
    """Runs analysis tasks in parallel.
    Supports both thread-based and process-based parallelism,
    with dependency ordering and progress reporting.
    """

    def __init__(
        self,
        max_workers: int = None,
        use_processes: bool = False,
        cache: TieredCache | None = None,
    ):
        self.max_workers = max_workers or min(os.cpu_count() or 4, 8)
        self.use_processes = use_processes
        self.cache = cache
        self.progress = ProgressReporter()

    def analyze_batch(
        self,
        tasks: list[AnalysisTask],
        analyze_fn: Callable[[Any], Any],
        on_complete: Callable[[AnalysisResult], None] | None = None,
    ) -> list[AnalysisResult]:
        """Analyze a batch of tasks in parallel."""
        results: list[AnalysisResult] = []
        ordered = self._order_tasks(tasks)
        self.progress.set_total(len(ordered))
        executor_class = ProcessPoolExecutor if self.use_processes else ThreadPoolExecutor
        with executor_class(max_workers=self.max_workers) as executor:
            futures = {}
            completed_ids = set()
            pending = list(ordered)
            while pending or futures:
                ready = [t for t in pending if all(d in completed_ids for d in t.dependencies)]
                for task in ready:
                    pending.remove(task)
                    future = executor.submit(self._run_task, task, analyze_fn)
                    futures[future] = task
                if futures:
                    done = next(as_completed(futures))
                    task = futures.pop(done)
                    try:
                        result = done.result()
                    except Exception as e:
                        result = AnalysisResult(
                            task_id=task.task_id,
                            success=False,
                            error=str(e),
                        )
                    results.append(result)
                    completed_ids.add(task.task_id)
                    self.progress.report_complete(result.success)
                    if on_complete:
                        on_complete(result)
        return results

    def _run_task(
        self,
        task: AnalysisTask,
        analyze_fn: Callable[[Any], Any],
    ) -> AnalysisResult:
        """Run a single analysis task."""
        start = time.time()
        try:
            result = analyze_fn(task.target)
            duration = time.time() - start
            return AnalysisResult(
                task_id=task.task_id,
                success=True,
                result=result,
                duration=duration,
            )
        except Exception as e:
            duration = time.time() - start
            return AnalysisResult(
                task_id=task.task_id,
                success=False,
                error=str(e),
                duration=duration,
            )

    def _order_tasks(self, tasks: list[AnalysisTask]) -> list[AnalysisTask]:
        """Order tasks by dependencies (topological sort)."""
        task_map = {t.task_id: t for t in tasks}
        result = []
        visited = set()
        temp = set()

        def visit(task_id: str) -> None:
            if task_id in visited:
                return
            if task_id in temp:
                return
            temp.add(task_id)
            task = task_map.get(task_id)
            if task:
                for dep in task.dependencies:
                    if dep in task_map:
                        visit(dep)
                visited.add(task_id)
                result.append(task)
            temp.discard(task_id)

        for task in tasks:
            visit(task.task_id)
        return result


class CachedAnalysis:
    """Wrapper that adds caching to any analysis function.
    Automatically caches results and handles invalidation.
    """

    def __init__(
        self,
        analyze_fn: Callable[[Any], Any],
        key_fn: Callable[[Any], CacheKey],
        cache: TieredCache | None = None,
    ):
        self.analyze_fn = analyze_fn
        self.key_fn = key_fn
        self.cache = cache or TieredCache()
        self._hits = 0
        self._misses = 0

    def __call__(self, target: Any) -> Any:
        """Run analysis with caching."""
        key = self.key_fn(target)
        cached = self.cache.get(key)
        if cached is not None:
            self._hits += 1
            return cached
        self._misses += 1
        result = self.analyze_fn(target)
        self.cache.put(key, result)
        return result

    def invalidate(self, target: Any) -> None:
        """Invalidate cached result."""
        key = self.key_fn(target)
        self.cache.remove(key)

    @property
    def hit_rate(self) -> float:
        """Get cache hit rate."""
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    def stats(self) -> dict[str, Any]:
        """Get statistics."""
        return {
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": self.hit_rate,
            "cache": self.cache.stats(),
        }


class InvalidationStrategy(Enum):
    """Cache invalidation strategies."""

    IMMEDIATE = auto()
    LAZY = auto()
    TIME_BASED = auto()
    DEPENDENCY = auto()


@dataclass
class InvalidationRule:
    """Rule for cache invalidation."""

    key_pattern: str
    strategy: InvalidationStrategy
    max_age_seconds: float | None = None
    dependencies: list[str] = field(default_factory=list)


class SmartInvalidator:
    """Manages smart cache invalidation.
    Tracks dependencies and applies invalidation rules
    to minimize unnecessary re-analysis.
    """

    def __init__(self, cache: TieredCache):
        self.cache = cache
        self.rules: list[InvalidationRule] = []
        self._stale: set[str] = set()
        self._timestamps: dict[str, float] = {}

    def add_rule(self, rule: InvalidationRule) -> None:
        """Add an invalidation rule."""
        self.rules.append(rule)

    def on_change(self, key: CacheKey) -> set[str]:
        """Handle a change event."""
        key_str = key.to_string()
        invalidated = set()
        for rule in self.rules:
            if self._matches_pattern(key_str, rule.key_pattern):
                if rule.strategy == InvalidationStrategy.IMMEDIATE:
                    self.cache.remove(key)
                    deps = self.cache.persistent.invalidate_dependencies(key)
                    invalidated.update(deps)
                    invalidated.add(key_str)
                elif rule.strategy == InvalidationStrategy.LAZY:
                    self._stale.add(key_str)
                elif rule.strategy == InvalidationStrategy.DEPENDENCY:
                    deps = self.cache.persistent.invalidate_dependencies(key)
                    invalidated.update(deps)
        return invalidated

    def is_stale(self, key: CacheKey) -> bool:
        """Check if a key is stale."""
        key_str = key.to_string()
        if key_str in self._stale:
            return True
        for rule in self.rules:
            if (
                rule.strategy == InvalidationStrategy.TIME_BASED
                and rule.max_age_seconds
                and self._matches_pattern(key_str, rule.key_pattern)
            ):
                created = self._timestamps.get(key_str, 0)
                if time.time() - created > rule.max_age_seconds:
                    return True
        return False

    def mark_fresh(self, key: CacheKey) -> None:
        """Mark a key as fresh."""
        key_str = key.to_string()
        self._stale.discard(key_str)
        self._timestamps[key_str] = time.time()

    def _matches_pattern(self, key: str, pattern: str) -> bool:
        """Check if key matches pattern."""
        import fnmatch

        return fnmatch.fnmatch(key, pattern)


class FileCache:
    """Cache for file-based analysis results.
    Tracks file hashes and only re-analyzes when content changes.
    """

    def __init__(self, cache: TieredCache = None):
        self.cache = cache or TieredCache()
        self._file_hashes: dict[str, str] = {}

    def get_or_analyze(
        self,
        path: Path,
        analyze_fn: Callable[[Path], Any],
    ) -> tuple[Any, bool]:
        """Get cached result or run analysis.
        Returns (result, was_cached).
        """
        path_str = str(path.absolute())
        current_hash = hash_file(path)
        cached_hash = self._file_hashes.get(path_str)
        if cached_hash == current_hash:
            key = CacheKey(CacheKeyType.MODULE, path_str)
            cached = self.cache.get(key)
            if cached is not None:
                return cached, True
        result = analyze_fn(path)
        self._file_hashes[path_str] = current_hash
        key = CacheKey(CacheKeyType.MODULE, path_str)
        self.cache.put(key, result)
        return result, False

    def invalidate(self, path: Path) -> None:
        """Invalidate cache for a file."""
        path_str = str(path.absolute())
        self._file_hashes.pop(path_str, None)
        key = CacheKey(CacheKeyType.MODULE, path_str)
        self.cache.remove(key)


__all__ = [
    "CacheKeyType",
    "CacheKey",
    "hash_bytecode",
    "hash_function",
    "hash_file",
    "hash_dict",
    "LRUCache",
    "CacheEntry",
    "PersistentCache",
    "TieredCache",
    "AnalysisTask",
    "AnalysisResult",
    "ProgressReporter",
    "ParallelAnalyzer",
    "CachedAnalysis",
    "InvalidationStrategy",
    "InvalidationRule",
    "SmartInvalidator",
    "FileCache",
]
