# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
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

"""Dependency-aware parallel analysis task orchestration.

Runs ``AnalysisTask`` instances in parallel via thread or process pools,
respecting inter-task dependencies through topological ordering.  Tasks
with unresolvable dependencies are reported as failures.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from concurrent.futures import Future, ProcessPoolExecutor, ThreadPoolExecutor, as_completed

from pysymex.analysis.runtime.cache.models import AnalysisTask, AnalysisResult
from pysymex.analysis.runtime.cache.progress import ProgressReporter
from pysymex.analysis.runtime.cache.tiered import TieredCache
from pysymex.logger import get_logger

logger = get_logger(__name__)


def _format_exception(exc: BaseException) -> str:
    """Format an exception class and its message into a stable diagnostic string.

    Args:
        exc (BaseException): The caught exception.

    Returns:
        str: The formatted diagnostic message string.
    """
    message = str(exc)
    if message:
        return f"{type(exc).__name__}: {message}"
    return type(exc).__name__


class ParallelAnalyzer:
    """Dependency-aware parallel task executor.

    Topologically orders tasks by dependencies, then submits ready tasks
    to a thread or process pool.  Reports progress via ``ProgressReporter``.
    """

    def __init__(
        self,
        max_workers: int | None = None,
        use_processes: bool = False,
        cache: TieredCache | None = None,
    ) -> None:
        """Initialize a ParallelAnalyzer instance for executing tasks.

        Args:
            max_workers (int | None): Limit on parallel concurrent executors.
            use_processes (bool): If True, use process workers instead of thread workers.
            cache (TieredCache | None): Optional cache backing.
        """
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
        """Execute *tasks* in parallel, respecting dependencies.

        Tasks are topologically sorted, then submitted as their
        dependencies complete.  Returns results in completion order.
        Tasks with circular or unresolvable dependencies are failed
        with an error message.

        Args:
            tasks: Analysis tasks with optional dependency lists.
            analyze_fn: Callable invoked with ``task.target``.
            on_complete: Optional callback invoked for each result.

        Returns:
            All ``AnalysisResult`` instances (success and failure).
        """
        results: list[AnalysisResult] = []
        ordered = self._order_tasks(tasks)
        self.progress.set_total(len(ordered))
        executor_class = ProcessPoolExecutor if self.use_processes else ThreadPoolExecutor
        with executor_class(max_workers=self.max_workers) as executor:
            futures: dict[Future[AnalysisResult], AnalysisTask] = {}
            completed_ids: set[str] = set()
            pending: list[AnalysisTask] = list(ordered)
            while pending or futures:
                ready = self._ready_tasks(pending, completed_ids)
                ready.sort()

                if not ready and not futures:
                    logger.warning("Parallel analysis batch has unresolvable dependencies")
                    for task in pending:
                        result = AnalysisResult(
                            task_id=task.task_id,
                            success=False,
                            error="Unresolvable dependency",
                        )
                        results.append(result)
                        completed_ids.add(task.task_id)
                        self.progress.report_complete(False)
                        if on_complete:
                            on_complete(result)
                    break
                for task in ready:
                    pending.remove(task)
                    future = executor.submit(self._run_task, task, analyze_fn)
                    futures[future] = task
                if futures:
                    done = next(as_completed(futures))
                    self._record_completed_future(
                        done, futures, results, completed_ids, on_complete
                    )
        return results

    @staticmethod
    def _ready_tasks(
        pending: list[AnalysisTask],
        completed_ids: set[str],
    ) -> list[AnalysisTask]:
        """Find pending tasks that have no outstanding unresolved dependencies.

        Args:
            pending (list[AnalysisTask]): A list of all pending tasks.
            completed_ids (set[str]): String IDs of successfully executed tasks.

        Returns:
            list[AnalysisTask]: Pending tasks ready to execute.
        """
        ready: list[AnalysisTask] = []
        for task in pending:
            can_run = True
            for dependency in task.dependencies:
                if dependency in completed_ids:
                    continue
                can_run = False
                break
            if can_run:
                ready.append(task)
        return ready

    def _record_completed_future(
        self,
        done: Future[AnalysisResult],
        futures: dict[Future[AnalysisResult], AnalysisTask],
        results: list[AnalysisResult],
        completed_ids: set[str],
        on_complete: Callable[[AnalysisResult], None] | None,
    ) -> None:
        """Retrieve results from a finished future and register completion.

        Args:
            done (Future[AnalysisResult]): The completed worker future.
            futures (dict[Future[AnalysisResult], AnalysisTask]): Active futures map.
            results (list[AnalysisResult]): Cumulative results list.
            completed_ids (set[str]): Set of completed task IDs.
            on_complete (Callable[[AnalysisResult], None] | None): Completed callback.
        """
        task = futures.pop(done)
        try:
            result = done.result()
        except Exception as e:
            logger.warning("Parallel analysis task failed: %s", task.task_id, exc_info=True)
            result = AnalysisResult(
                task_id=task.task_id,
                success=False,
                error=_format_exception(e),
            )
        results.append(result)
        completed_ids.add(task.task_id)
        self.progress.report_complete(result.success)
        if on_complete:
            on_complete(result)

    def _run_task(
        self,
        task: AnalysisTask,
        analyze_fn: Callable[[object], object],
    ) -> AnalysisResult:
        """Execute a single task, returning an ``AnalysisResult`` with wall-clock duration."""
        start = time.time()
        try:
            result = analyze_fn(task.target)
            duration = time.time() - start
            return AnalysisResult(task.task_id, True, result=result, duration=duration)
        except Exception as e:
            logger.warning("Analysis task execution failed: %s", task.task_id, exc_info=True)
            duration = time.time() - start
            return AnalysisResult(
                task.task_id,
                False,
                error=_format_exception(e),
                duration=duration,
            )

    def _order_tasks(self, tasks: list[AnalysisTask]) -> list[AnalysisTask]:
        """Topologically sort *tasks* by dependencies (DFS, cycle-tolerant)."""
        task_map = {t.task_id: t for t in tasks}
        result: list[AnalysisTask] = []
        visited: set[str] = set()
        temp: set[str] = set()

        def visit(task_id: str) -> None:
            if task_id in visited or task_id in temp:
                return
            temp.add(task_id)
            task = task_map.get(task_id)
            if task:
                for dependency in task.dependencies:
                    if dependency in task_map:
                        visit(dependency)
                visited.add(task_id)
                result.append(task)
            temp.discard(task_id)

        for task in tasks:
            visit(task.task_id)
        return result


__all__ = ["ParallelAnalyzer"]
