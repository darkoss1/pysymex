# pysymex: Python Symbolic Execution & Formal Verification
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

"""Parallel path exploration core logic for pysymex.

Work queues, state merging, parallel explorer, constraint partitioning,
parallel solver, and process-based file verification.
"""

from __future__ import annotations

import logging
import os
import queue
import threading
import time
from importlib import import_module
from collections.abc import Callable, Sequence
from concurrent.futures import Future, ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from typing import (
    Any,
    Generic,
    TypeVar,
)

import z3

from pysymex.core.solver.constraints import structural_hash
from pysymex.core.solver.independence import ConstraintIndependenceOptimizer
from pysymex.core.parallel.types import (
    ExplorationConfig,
    ExplorationResult,
    ExplorationStrategy,
    PathResult,
    StateSignature,
    WorkItem,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


class WorkQueue(Generic[T]):
    """Thread-safe priority queue for symbolic execution work items.

    Wraps :class:`queue.PriorityQueue` with an atomic item counter and
    auto-incrementing IDs so each work item has a unique, monotonic
    ``path_id`` suitable for deterministic replay.

    Args:
        maxsize: Maximum queue capacity (0 = unbounded).
    """

    def __init__(self, maxsize: int = 0) -> None:
        """Initialize the work queue.

        Args:
            maxsize: Maximum number of items the queue can hold. 0 means unbounded.
        """
        self._queue: queue.PriorityQueue[WorkItem[T]] = queue.PriorityQueue(maxsize)
        self._lock = threading.Lock()
        self._item_count = 0
        self._next_id = 0

    def put(
        self, state: T, priority: float = 0.0, depth: int = 0, parent_id: int | None = None
    ) -> int:
        """Add a work item to the queue."""
        with self._lock:
            item_id = self._next_id
            self._next_id += 1
            self._item_count += 1
        item = WorkItem(
            state=state,
            priority=priority,
            depth=depth,
            path_id=item_id,
            parent_id=parent_id,
        )
        self._queue.put(item)
        return item_id

    def get(self, timeout: float | None = None) -> WorkItem[T] | None:
        """Get the highest priority work item."""
        try:
            item = self._queue.get(timeout=timeout)
            with self._lock:
                self._item_count -= 1
            return item
        except queue.Empty:
            return None

    def empty(self) -> bool:
        """Check if the queue is empty."""
        with self._lock:
            return self._queue.empty() and self._item_count == 0

    def size(self) -> int:
        """Get the approximate queue size."""
        with self._lock:
            return self._item_count

    def clear(self) -> None:
        """Clear all items from the queue."""
        while not self.empty():
            try:
                self._queue.get_nowait()
            except queue.Empty:
                break
        with self._lock:
            self._item_count = 0


class StateMerger(Generic[T]):
    """Merges similar symbolic states to reduce path explosion.

    States are grouped by a structural :class:`StateSignature`
    (PC, stack depth, local-variable keys, constraint hash).
    Once ``merge_threshold`` states share the same signature,
    they are merged into one via :meth:`merge_states`.

    Subclass and override :meth:`merge_states` for domain-specific
    merging logic.

    Args:
        merge_threshold: Number of similar states that triggers a merge.
    """

    def __init__(self, merge_threshold: int = 10) -> None:
        """Initialize the state merger.

        Args:
            merge_threshold: Minimum number of states with identical signatures
                required to trigger an automated merge operation.
        """
        self._pending: dict[StateSignature, list[T]] = {}
        self._merge_threshold = merge_threshold
        self._lock = threading.Lock()
        self._merge_count = 0

    def get_signature(self, state: object) -> StateSignature:
        """Compute a structural signature for the given symbolic state.

        The signature includes:
        - pc: The current program counter offset.
        - stack_depth: Current size of the symbolic stack.
        - local_keys: Names of all variables currently in scope.
        - constraint_hash: A fast structural hash of the first few path constraints.
        - constraint_discriminator: A collision-resistant tuple of Z3 expression hashes.

        This signature is used to identify execution paths that have converged
        on the same symbolic state, allowing them to be merged to mitigate
        path explosion.
        """
        pc = getattr(state, "pc", 0)
        stack = getattr(state, "stack", [])
        locals_dict = getattr(state, "locals", {})
        constraints = getattr(state, "constraints", [])

        try:
            head = constraints[:5]
            constraint_hash_val = structural_hash(head, None)  # Temporary hasher for one-off call
            constraint_disc = (len(constraints), *tuple(sorted(c.hash() for c in head)))
        except (TypeError, RecursionError):
            constraint_hash_val = hash(len(constraints))
            constraint_disc = (len(constraints),)
        return StateSignature(
            pc=pc,
            stack_depth=len(stack),
            local_keys=frozenset(locals_dict.keys()),
            constraint_hash=constraint_hash_val,
            constraint_discriminator=constraint_disc,
        )

    def should_merge(self, state: T) -> list[T] | None:
        """Check if the given state should be merged."""
        sig = self.get_signature(state)
        with self._lock:
            if sig not in self._pending:
                self._pending[sig] = []
            self._pending[sig].append(state)
            if len(self._pending[sig]) >= self._merge_threshold:
                return self._pending.pop(sig)
        return None

    def merge_states(self, states: list[T]) -> T:
        """Merge multiple states into one. Default implementation returns the first state."""
        with self._lock:
            self._merge_count += 1
        return states[0]

    def get_merge_count(self) -> int:
        """Get the total number of merges performed."""
        with self._lock:
            return self._merge_count

    def flush_pending(self) -> list[T]:
        """Return all pending states that haven't been merged yet."""
        with self._lock:
            all_states: list[T] = []
            for states in self._pending.values():
                all_states.extend(states)
            self._pending.clear()
            return all_states


class ParallelExplorer(Generic[T]):
    """Parallel path exploration engine for symbolic execution.

    Coordinates multiple worker threads to explore paths in parallel,
    leveraging a thread-safe work queue and state merging to optimize
    exploration efficiency.

    Args:
        config: Configuration parameters for exploration limits and strategy.
        step_function: Callback to generate successor states from a given state.
        check_function: Optional callback to inspect states for bugs/vulnerabilities.
    """

    def __init__(
        self,
        config: ExplorationConfig | None = None,
        step_function: Callable[[T], list[T]] | None = None,
        check_function: Callable[[T], list[dict[str, object]]] | None = None,
    ) -> None:
        """Initialize the parallel explorer."""
        self.config = config or ExplorationConfig()
        self._step_fn = step_function
        self._check_fn = check_function
        self._work_queue: WorkQueue[T] = WorkQueue(self.config.max_queue_size)
        self._result = ExplorationResult()
        self._result_lock = threading.Lock()
        self._merger = StateMerger[T](self.config.merge_threshold)
        self._running = False
        self._stop_event = threading.Event()
        self._coverage: set[int] = set()
        self._coverage_lock = threading.Lock()

    def set_step_function(self, fn: Callable[[T], list[T]]) -> None:
        """Set the function that steps a state to successors."""
        self._step_fn = fn

    def set_check_function(self, fn: Callable[[T], list[dict[str, object]]]) -> None:
        """Set the function that checks a state for issues."""
        self._check_fn = fn

    def add_initial_state(self, state: T, priority: float = 0.0) -> None:
        """Add an initial state to explore."""
        self._work_queue.put(state, priority=priority, depth=0)

    def explore(self) -> ExplorationResult:
        """Run parallel exploration and return results."""
        if self._step_fn is None:
            raise ValueError("Step function not set")
        self._running = True
        self._stop_event.clear()
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures: list[Future[None]] = []
            for worker_id in range(self.config.max_workers):
                future = executor.submit(self._worker_loop, worker_id)
                futures.append(future)
            worker_errors: list[Exception] = []
            try:
                for future in as_completed(futures, timeout=self.config.timeout_seconds):
                    try:
                        future.result()
                    except Exception as exc:
                        worker_errors.append(exc)
            except TimeoutError:
                self._stop_event.set()
                executor.shutdown(wait=False, cancel_futures=True)
            if worker_errors:
                self._stop_event.set()
                raise ExceptionGroup(
                    f"parallel exploration: {len(worker_errors)} worker(s) failed",
                    worker_errors,
                )
        self._running = False
        self._result.time_seconds = time.time() - start_time
        self._result.workers_used = self.config.max_workers
        self._result.states_merged = self._merger.get_merge_count()
        remaining = self._merger.flush_pending()
        for state in remaining:
            self._work_queue.put(state)
        return self._result

    def _worker_loop(self, worker_id: int) -> None:
        """Main worker loop."""
        paths_explored = 0
        max_paths = self.config.max_paths_per_worker
        while not self._stop_event.is_set() and paths_explored < max_paths:
            if self._process_next_item(worker_id):
                paths_explored += 1
            elif self._work_queue.empty():
                time.sleep(0.05)
                if self._work_queue.empty():
                    break

    def _process_next_item(self, worker_id: int) -> bool:
        """Process a single work item from the queue. Returns True if a path was fully explored."""
        item = self._work_queue.get(timeout=0.1)
        if item is None:
            return False

        if self.config.enable_state_merging:
            merge_candidates = self._merger.should_merge(item.state)
            if merge_candidates:
                merged_state = self._merger.merge_states(merge_candidates)
                self._work_queue.put(
                    merged_state,
                    priority=item.priority,
                    depth=item.depth,
                    parent_id=item.path_id,
                )
                return False

        result = self._explore_path(item, worker_id)
        with self._result_lock:
            self._result.add_path_result(result, worker_id)
        return True

    def _explore_path(self, item: WorkItem[T], worker_id: int) -> PathResult:
        """Explore a single path."""
        start_time = time.time()
        issues: list[dict[str, object]] = []
        coverage: set[int] = set()
        status = "completed"
        error: str | None = None
        try:
            if self._check_fn:
                found = self._check_fn(item.state)
                issues.extend(found)
            pc = getattr(item.state, "pc", 0)
            with self._coverage_lock:
                self._coverage.add(pc)
            coverage.add(pc)
            if self._step_fn:
                successors = self._step_fn(item.state)
                for successor in successors:
                    priority = self._compute_priority(successor, item)
                    self._work_queue.put(
                        successor,
                        priority=priority,
                        depth=item.depth + 1,
                        parent_id=item.path_id,
                    )
        except TimeoutError:
            status = "timeout"
        except Exception as e:
            status = "error"
            error = str(e)
        return PathResult(
            path_id=item.path_id,
            status=status,
            issues=issues,
            coverage=coverage,
            time_seconds=time.time() - start_time,
            error=error,
        )

    def _compute_priority(self, state: T, parent: WorkItem[T]) -> float:
        """Compute priority for a successor state."""
        strategy = self.config.strategy
        if strategy == ExplorationStrategy.ADAPTIVE:
            depth = float(parent.depth + 1)
            pc = float(getattr(state, "pc", 0))
            with self._coverage_lock:
                is_new_pc = 1.0 if int(pc) not in self._coverage else 0.0
            return -((depth * 8.0) + (is_new_pc * 120.0) + pc)
        elif strategy == ExplorationStrategy.CHTD_NATIVE:
            depth = float(parent.depth + 1)
            pc = float(getattr(state, "pc", 0))
            return -(depth * 10.0 + pc)
        elif strategy == ExplorationStrategy.COVERAGE:
            pc = getattr(state, "pc", 0)
            with self._coverage_lock:
                if pc not in self._coverage:
                    return 1000.0
            return 0.0
        elif strategy == ExplorationStrategy.RANDOM:
            import random

            return random.random()
        else:
            return parent.priority

    def stop(self) -> None:
        """Stop exploration."""
        self._stop_event.set()

    def get_coverage(self) -> set[int]:
        """Get the set of covered program counters."""
        with self._coverage_lock:
            return set(self._coverage)


class ConstraintPartitioner:
    """Partitions Z3 constraints into independent sets for parallel solving.

    Two constraints are considered *dependent* if they share at least
    one free variable.  The partitioner uses a union-find structure to
    group dependent constraints, so each resulting partition can be
    solved independently - and therefore in parallel.
    """

    def __init__(self) -> None:
        self._variable_graph: dict[str, set[str]] = {}

    def partition(self, constraints: list[z3.BoolRef]) -> list[list[z3.BoolRef]]:
        """Partition constraints into independent sets."""
        if not constraints:
            return []

        optimizer = ConstraintIndependenceOptimizer()
        constraint_vars: list[frozenset[str]] = []
        for c in constraints:
            constraint_vars.append(optimizer.register_constraint(c))

        partitions: dict[str, list[z3.BoolRef]] = {}
        for c, var_names in zip(constraints, constraint_vars, strict=False):
            if not var_names:
                root = "CONST"
            else:
                root = optimizer.find_group_root(next(iter(var_names)))
            if root not in partitions:
                partitions[root] = []
            partitions[root].append(c)
        return list(partitions.values())


class ParallelSolver:
    """Parallel constraint solver using constraint partitioning.

    Splits a constraint set via :class:`ConstraintPartitioner`, solves
    each partition concurrently in a :class:`ThreadPoolExecutor`, and
    combines the per-partition models.

    Args:
        max_workers: Maximum solver threads.
        timeout_ms: Per-partition solver timeout in milliseconds.
    """

    def __init__(self, max_workers: int = 4, timeout_ms: int = 5000) -> None:
        self.max_workers = max_workers
        self.timeout_ms = timeout_ms
        self._partitioner = ConstraintPartitioner()

    def check(self, constraints: list[z3.BoolRef]) -> tuple[bool, z3.ModelRef | None]:
        """Check satisfiability using parallel solving.
        Returns (is_sat, model).
        """
        if not constraints:
            return True, None
        partitions = self._partitioner.partition(constraints)
        if len(partitions) == 1:
            return self._solve_partition(partitions[0])
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self._solve_partition, part) for part in partitions]
            models: list[z3.ModelRef] = []
            errors: list[Exception] = []
            for future in as_completed(futures, timeout=self.timeout_ms / 1000):
                try:
                    is_sat, model = future.result()
                    if not is_sat:
                        return False, None
                    if model:
                        models.append(model)
                except (z3.Z3Exception, RuntimeError, TimeoutError) as exc:
                    errors.append(exc)
            if errors:
                raise ExceptionGroup(
                    f"parallel solver: {len(errors)} partition(s) failed",
                    errors,
                )
        combined_model = self._combine_models(models)
        return True, combined_model

    def _solve_partition(self, constraints: list[z3.BoolRef]) -> tuple[bool, z3.ModelRef | None]:
        """Solve a single partition."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        solver.add(constraints)
        result = solver.check()
        if result == z3.sat:
            return True, solver.model()
        return False, None

    def _combine_models(self, models: list[z3.ModelRef]) -> z3.ModelRef | None:
        """Combine multiple models into one.

        Creates a fresh solver, asserts all variable assignments from each
        partition model, and returns the combined model.
        """
        if not models:
            return None
        if len(models) == 1:
            return models[0]

        combined = z3.Solver()
        for model in models:
            for decl in model.decls():
                eq = decl() == model[decl]
                combined.add(eq if isinstance(eq, z3.BoolRef) else z3.BoolVal(bool(eq)))
        if combined.check() == z3.sat:
            return combined.model()
        return models[0]


class ProcessParallelVerifier:
    """Process-based parallel file verification.

    Uses ProcessPoolExecutor (not ThreadPoolExecutor) to bypass the GIL
    for CPU-bound Z3 solver work. Each worker process creates its own
    Z3 context and solver instances.

    Args:
        max_workers: Maximum number of worker processes. Defaults to CPU count.
        timeout_ms: Per-file solver timeout in milliseconds.
    """

    def __init__(
        self,
        max_workers: int | None = None,
        timeout_ms: int = 5000,
    ) -> None:
        self._max_workers = max_workers or min(os.cpu_count() or 2, 8)
        self._timeout_ms = timeout_ms

    def verify_files(
        self,
        file_paths: Sequence[str],
        max_depth: int = 50,
    ) -> dict[str, object]:
        """Verify multiple files in parallel using separate processes.

        Args:
            file_paths: Sequence of Python file paths to verify.
            max_depth: Maximum symbolic execution depth.

        Returns:
            Dictionary mapping file paths to their verification results.
        """
        if not file_paths:
            return {}

        paths = list(file_paths)
        if len(paths) == 1 or self._max_workers <= 1:
            return self._verify_sequential(paths, max_depth)
        try:
            return self._verify_parallel(paths, max_depth)
        except* TimeoutError as eg:
            logger.warning("%d timeout(s) in parallel verification", len(eg.exceptions))
        except* Exception as eg:
            logger.warning("%d error(s) in parallel verification", len(eg.exceptions))
        return self._verify_sequential(paths, max_depth)

    def _verify_sequential(self, file_paths: list[str], max_depth: int) -> dict[str, object]:
        """Verify sequential."""
        results: dict[str, object] = {}
        for path in file_paths:
            try:
                result = _process_verify_file(path, self._timeout_ms, max_depth)
                if result is not None:
                    results[path] = result
            except Exception as e:
                import traceback

                logger.error("Sequential verification error in %s: %s", path, e)
                traceback.print_exc()
        return results

    def _verify_parallel(self, file_paths: list[str], max_depth: int) -> dict[str, object]:
        """Verify parallel."""
        results: dict[str, object] = {}
        errors: list[Exception] = []
        with ProcessPoolExecutor(max_workers=self._max_workers) as pool:
            future_to_path = {
                pool.submit(_process_verify_file, path, self._timeout_ms, max_depth): path
                for path in file_paths
            }
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result(timeout=self._timeout_ms / 1000 * 3)
                    if result is not None:
                        results[path] = result
                except Exception as exc:
                    errors.append(exc)
        if errors:
            raise ExceptionGroup(
                f"parallel verification: {len(errors)} file(s) failed",
                errors,
            )
        return results


def _serialize_file_results(
    filepath: str, file_results: dict[str, list[Any]]
) -> dict[str, list[dict[str, object]]]:
    """Serialize verify results to be cross-process compatible."""
    serialized: dict[str, list[dict[str, object]]] = {}
    for func_name, results in file_results.items():
        serialized[func_name] = []
        for r in results:
            crash = getattr(r, "crash", None)
            bug_type = getattr(getattr(crash, "bug_type", None), "value", "")
            serialized[func_name].append(
                {
                    "can_crash": bool(getattr(r, "can_crash", False)),
                    "proven_safe": bool(getattr(r, "proven_safe", False)),
                    "z3_status": str(getattr(r, "z3_status", "unknown")),
                    "verification_time_ms": float(getattr(r, "verification_time_ms", 0.0)),
                    "bug_type": str(bug_type),
                    "line": int(getattr(crash, "line", 0) or 0),
                    "function": str(getattr(crash, "function", "") or ""),
                    "description": str(getattr(crash, "description", "") or ""),
                    "file_path": filepath,
                }
            )
    return serialized


def _process_verify_file(
    filepath: str, timeout_ms: int, max_depth: int
) -> dict[str, list[dict[str, object]]] | None:
    """Top-level worker function for process-based file verification.

    Must be module-level (not a method) for ProcessPoolExecutor pickling.
    Each process gets its own Z3 context.
    """
    try:
        solver_module = import_module("pysymex.analysis.solver")
        z3_engine_cls = getattr(solver_module, "Z3Engine")

        engine = z3_engine_cls(timeout_ms=timeout_ms, max_depth=max_depth, max_workers=1)
        file_results = engine.verify_file(filepath)
        if not file_results:
            return None

        return _serialize_file_results(filepath, file_results)
    except Exception as e:
        import traceback

        logger.error("Worker process error in %s: %s", filepath, e)
        traceback.print_exc()
        return None


__all__ = [
    "ConstraintPartitioner",
    "ParallelExplorer",
    "ParallelSolver",
    "ProcessParallelVerifier",
    "StateMerger",
    "WorkQueue",
]
