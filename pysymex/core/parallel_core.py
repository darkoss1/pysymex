"""Parallel path exploration core logic for pysymex.

Work queues, state merging, parallel explorer, constraint partitioning,
parallel solver, and process-based file verification.
"""

from __future__ import annotations


import os

import queue

import threading

import time

from collections.abc import Callable

from concurrent.futures import Future, ProcessPoolExecutor, ThreadPoolExecutor, as_completed

from typing import (
    Any,
    Generic,
    TypeVar,
)


import z3


from pysymex.core.constraint_hash import structural_hash

from pysymex.core.parallel_types import (
    ExplorationConfig,
    ExplorationResult,
    ExplorationStrategy,
    PathResult,
    StateSignature,
    WorkItem,
)

T = TypeVar("T")


class WorkQueue(Generic[T]):
    """Thread-safe priority queue for work items."""

    def __init__(self, maxsize: int = 0):
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

        return self._queue.empty()

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
    """Merges similar states to reduce path explosion."""

    def __init__(self, merge_threshold: int = 10):
        self._pending: dict[StateSignature, list[T]] = {}

        self._merge_threshold = merge_threshold

        self._lock = threading.Lock()

        self._merge_count = 0

    def get_signature(self, state: Any) -> StateSignature:
        """Compute signature for a state."""

        pc = getattr(state, "pc", 0)

        stack = getattr(state, "stack", [])

        locals_dict = getattr(state, "locals", {})

        constraints = getattr(state, "constraints", [])

        try:
            constraint_hash_val = structural_hash(constraints[:5])

        except Exception:
            constraint_hash_val = hash(len(constraints))

        return StateSignature(
            pc=pc,
            stack_depth=len(stack),
            local_keys=frozenset(locals_dict.keys()),
            constraint_hash=constraint_hash_val,
        )

    def should_merge(self, state: T) -> list[T] | None:
        """Check if state should be merged with pending states.
        Returns list of states to merge with, or None if not ready.
        """

        sig = self.get_signature(state)

        with self._lock:
            if sig not in self._pending:
                self._pending[sig] = []

            self._pending[sig].append(state)

            if len(self._pending[sig]) >= self._merge_threshold:
                states = self._pending.pop(sig)

                self._merge_count += 1

                return states

        return None

    def merge_states(self, states: list[T]) -> T:
        """Merge multiple states into one.
        Default implementation returns first state.
        Subclasses should implement proper merging.
        """

        return states[0]

    def get_merge_count(self) -> int:
        """Get the number of merges performed."""

        return self._merge_count

    def flush_pending(self) -> list[T]:
        """Flush all pending states."""

        with self._lock:
            all_states: list[T] = []

            for states in self._pending.values():
                all_states.extend(states)

            self._pending.clear()

            return all_states


class ParallelExplorer(Generic[T]):
    """Parallel symbolic execution engine.
    Distributes path exploration across multiple worker threads
    with work stealing and result aggregation.
    """

    def __init__(
        self,
        config: ExplorationConfig | None = None,
        step_function: Callable[[T], list[T]] | None = None,
        check_function: Callable[[T], list[dict[str, Any]]] | None = None,
    ):
        self.config = config or ExplorationConfig()

        self._step_fn = step_function

        self._check_fn = check_function

        self._work_queue: WorkQueue[T] = WorkQueue()

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

    def set_check_function(self, fn: Callable[[T], list[dict[str, Any]]]) -> None:
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

            try:
                for future in as_completed(futures, timeout=self.config.timeout_seconds):
                    future.result()

            except TimeoutError:
                self._stop_event.set()

            except Exception:
                self._stop_event.set()

                raise

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

        result = PathResult(path_id=item.path_id, status="completed")

        try:
            if self._check_fn:
                issues = self._check_fn(item.state)

                result.issues.extend(issues)

            pc = getattr(item.state, "pc", 0)

            with self._coverage_lock:
                self._coverage.add(pc)

            result.coverage.add(pc)

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
            result.status = "timeout"

        except Exception as e:
            result.status = "error"

            result.error = str(e)

        result.time_seconds = time.time() - start_time

        return result

    def _compute_priority(self, state: T, parent: WorkItem[T]) -> float:
        """Compute priority for a successor state."""

        strategy = self.config.strategy

        if strategy == ExplorationStrategy.DFS:
            return float(parent.depth + 1)

        elif strategy == ExplorationStrategy.BFS:
            return -float(parent.depth + 1)

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
    """Partitions constraints for parallel solving.
    Identifies independent constraint sets that can be
    solved in parallel.
    """

    def __init__(self):
        self._variable_graph: dict[str, set[str]] = {}

    def partition(self, constraints: list[z3.BoolRef]) -> list[list[z3.BoolRef]]:
        """Partition constraints into independent sets."""

        if not constraints:
            return []

        constraint_vars: list[set[str]] = []

        for c in constraints:
            vars_set = self._extract_variables(c)

            constraint_vars.append(vars_set)

        parent = list(range(len(constraints)))

        def find(x: int) -> int:
            if parent[x] != x:
                parent[x] = find(parent[x])

            return parent[x]

        def union(x: int, y: int) -> None:
            px, py = find(x), find(y)

            if px != py:
                parent[px] = py

        for i in range(len(constraints)):
            for j in range(i + 1, len(constraints)):
                if constraint_vars[i] & constraint_vars[j]:
                    union(i, j)

        partitions: dict[int, list[z3.BoolRef]] = {}

        for i, c in enumerate(constraints):
            root = find(i)

            if root not in partitions:
                partitions[root] = []

            partitions[root].append(c)

        return list(partitions.values())

    def _extract_variables(self, expr: z3.ExprRef) -> set[str]:
        """Extract variable names from a Z3 expression."""

        variables: set[str] = set()

        def visit(e: z3.ExprRef) -> None:
            if z3.is_const(e) and e.decl().kind() == z3.Z3_OP_UNINTERPRETED:
                variables.add(e.decl().name())

            else:
                for child in e.children():
                    visit(child)

        visit(expr)

        return variables


class ParallelSolver:
    """Parallel constraint solver using partitioning."""

    def __init__(self, max_workers: int = 4, timeout_ms: int = 5000):
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

            for future in as_completed(futures):
                is_sat, model = future.result()

                if not is_sat:
                    return False, None

                if model:
                    models.append(model)

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
        """Combine multiple models into one."""

        if not models:
            return None

        if len(models) == 1:
            return models[0]

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
        file_paths: list[str],
        max_depth: int = 50,
    ) -> dict[str, Any]:
        """Verify multiple files in parallel using separate processes.

        Args:
            file_paths: List of Python file paths to verify.
            max_depth: Maximum symbolic execution depth.

        Returns:
            Dictionary mapping file paths to their verification results.
        """

        if not file_paths:
            return {}

        if len(file_paths) == 1 or self._max_workers <= 1:
            return self._verify_sequential(file_paths, max_depth)

        return self._verify_parallel(file_paths, max_depth)

    def _verify_sequential(self, file_paths: list[str], max_depth: int) -> dict[str, Any]:
        results: dict[str, Any] = {}

        for path in file_paths:
            try:
                result = _process_verify_file(path, self._timeout_ms, max_depth)

                if result is not None:
                    results[path] = result

            except Exception as e:
                import traceback

                print(f"Sequential verification error in {path}: {e}")

                traceback.print_exc()

        return results

    def _verify_parallel(self, file_paths: list[str], max_depth: int) -> dict[str, Any]:
        results: dict[str, Any] = {}

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

                except Exception as e:
                    import traceback

                    print(f"Parallel verification error in {path}: {e}")

                    traceback.print_exc()

        return results


def _serialize_file_results(
    filepath: str, file_results: dict[str, list[Any]]
) -> dict[str, list[dict[str, Any]]]:
    """Serialize verify results to be cross-process compatible."""

    serialized: dict[str, list[dict[str, Any]]] = {}

    for func_name, results in file_results.items():
        serialized[func_name] = []

        for r in results:
            serialized[func_name].append(
                {
                    "can_crash": r.can_crash,
                    "proven_safe": r.proven_safe,
                    "z3_status": r.z3_status,
                    "verification_time_ms": r.verification_time_ms,
                    "bug_type": r.crash.bug_type.value if r.crash else "",
                    "line": r.crash.line if r.crash else 0,
                    "function": r.crash.function if r.crash else "",
                    "description": r.crash.description if r.crash else "",
                    "file_path": filepath,
                }
            )

    return serialized


def _process_verify_file(filepath: str, timeout_ms: int, max_depth: int) -> dict[str, Any] | None:
    """Top-level worker function for process-based file verification.

    Must be module-level (not a method) for ProcessPoolExecutor pickling.
    Each process gets its own Z3 context.
    """

    try:
        from pysymex.analysis.solver import Z3Engine

        engine = Z3Engine(timeout_ms=timeout_ms, max_depth=max_depth, max_workers=1)

        file_results = engine.verify_file(filepath)

        if not file_results:
            return None

        return _serialize_file_results(filepath, file_results)

    except Exception as e:
        import traceback

        print(f"Worker process error in {filepath}: {e}")

        traceback.print_exc()

        return None


__all__ = [
    "WorkQueue",
    "StateMerger",
    "ParallelExplorer",
    "ConstraintPartitioner",
    "ParallelSolver",
    "ProcessParallelVerifier",
]
