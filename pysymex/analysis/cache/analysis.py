"""Parallel analysis infrastructure: tasks, results, progress reporting,
parallel execution, and cached analysis wrapper.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future, ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

from pysymex.analysis.cache.core import CacheKey, TieredCache

logger = logging.getLogger(__name__)


@dataclass
class AnalysisTask:
    """A task for parallel analysis."""

    task_id: str
    target: Any
    priority: int = 0
    dependencies: list[str] = field(default_factory=lambda: [])

    def __lt__(self, other: AnalysisTask) -> bool:
        return self.priority > other.priority


@dataclass
class AnalysisResult:
    """Result of an analysis task."""

    task_id: str
    success: bool
    result: object = None
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
            completed = self.completed
            total = self.total
            failed = self.failed
            callbacks = list(self._callbacks)
        for callback in callbacks:
            try:
                callback(completed, total, failed)
            except Exception:
                logger.debug("Progress callback failed", exc_info=True)

    def on_progress(self, callback: Callable[[int, int, int], None]) -> None:
        """Register progress callback."""
        with self._lock:
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
        max_workers: int | None = None,
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
        analyze_fn: Callable[[object], object],
        on_complete: Callable[[AnalysisResult], None] | None = None,
    ) -> list[AnalysisResult]:
        """Analyze a batch of tasks in parallel."""
        results: list[AnalysisResult] = []
        ordered = self._order_tasks(tasks)
        self.progress.set_total(len(ordered))
        executor_class = ProcessPoolExecutor if self.use_processes else ThreadPoolExecutor
        with executor_class(max_workers=self.max_workers) as executor:
            futures: dict[Future[AnalysisResult], AnalysisTask] = {}
            completed_ids: set[str] = set()
            pending = list(ordered)
            while pending or futures:
                ready = [t for t in pending if all(d in completed_ids for d in t.dependencies)]
                # Ensure we submit highest priority tasks first
                ready.sort()

                if not ready and not futures:
                    for task in pending:
                        results.append(
                            AnalysisResult(
                                task_id=task.task_id,
                                success=False,
                                error="Unresolvable dependency",
                            )
                        )
                    break
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
        analyze_fn: Callable[[object], object],
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
        result: list[AnalysisTask] = []
        visited: set[str] = set()
        temp: set[str] = set()

        def visit(task_id: str) -> None:
            """Visit."""
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
        analyze_fn: Callable[[object], object],
        key_fn: Callable[[object], CacheKey],
        cache: TieredCache | None = None,
    ):
        self.analyze_fn = analyze_fn
        self.key_fn = key_fn
        self.cache = cache or TieredCache()
        self._hits = 0
        self._misses = 0

    def __call__(self, target: object) -> object:
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

    def invalidate(self, target: object) -> None:
        """Invalidate cached result."""
        key = self.key_fn(target)
        self.cache.remove(key)

    @property
    def hit_rate(self) -> float:
        """Get cache hit rate."""
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    def stats(self) -> dict[str, object]:
        """Get statistics."""
        return {
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": self.hit_rate,
            "cache": self.cache.stats(),
        }
