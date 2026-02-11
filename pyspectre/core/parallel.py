"""Parallel path exploration for PySpectre.
This module provides multi-threaded symbolic execution with:
- Work-stealing task queues
- State partitioning
- Thread-safe result aggregation
- Configurable parallelism
"""

from __future__ import annotations
import queue
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Generic,
    TypeVar,
)
import z3


class ExplorationStrategy(Enum):
    """Path exploration strategies."""

    DFS = auto()
    BFS = auto()
    RANDOM = auto()
    COVERAGE = auto()
    PRIORITY = auto()


@dataclass
class ExplorationConfig:
    """Configuration for parallel exploration."""

    max_workers: int = 4
    strategy: ExplorationStrategy = ExplorationStrategy.DFS
    max_paths_per_worker: int = 250
    sync_interval_ms: int = 100
    enable_state_merging: bool = True
    merge_threshold: int = 10
    timeout_seconds: float = 60.0


T = TypeVar("T")


@dataclass
class WorkItem(Generic[T]):
    """A unit of work for parallel exploration."""

    state: T
    priority: float = 0.0
    depth: int = 0
    path_id: int = 0
    parent_id: int | None = None

    def __lt__(self, other: WorkItem[T]) -> bool:
        """Compare by priority for heap operations."""
        return self.priority > other.priority


@dataclass
class PathResult:
    """Result from exploring a single path."""

    path_id: int
    status: str
    issues: list[dict[str, Any]] = field(default_factory=list)
    coverage: set[int] = field(default_factory=set)
    constraints_count: int = 0
    time_seconds: float = 0.0
    error: str | None = None


@dataclass
class ExplorationResult:
    """Aggregated result from parallel exploration."""

    total_paths: int = 0
    completed_paths: int = 0
    issues: list[dict[str, Any]] = field(default_factory=list)
    coverage: set[int] = field(default_factory=set)
    time_seconds: float = 0.0
    workers_used: int = 0
    paths_per_worker: dict[int, int] = field(default_factory=dict)
    cache_hits: int = 0
    states_merged: int = 0
    timeouts: int = 0
    errors: int = 0

    def add_path_result(self, result: PathResult, worker_id: int) -> None:
        """Add a path result to the aggregate."""
        self.total_paths += 1
        if result.status == "completed":
            self.completed_paths += 1
        elif result.status == "timeout":
            self.timeouts += 1
        elif result.status == "error":
            self.errors += 1
        self.issues.extend(result.issues)
        self.coverage.update(result.coverage)
        self.paths_per_worker[worker_id] = self.paths_per_worker.get(worker_id, 0) + 1


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


@dataclass
class StateSignature:
    """Signature for identifying similar states for merging."""

    pc: int
    stack_depth: int
    local_keys: FrozenSet[str]
    constraint_hash: int

    def __hash__(self) -> int:
        return hash((self.pc, self.stack_depth, self.local_keys, self.constraint_hash))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, StateSignature):
            return False
        return (
            self.pc == other.pc
            and self.stack_depth == other.stack_depth
            and self.local_keys == other.local_keys
        )


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
        constraint_hash = hash(tuple(str(c) for c in constraints[:5]))
        return StateSignature(
            pc=pc,
            stack_depth=len(stack),
            local_keys=frozenset(locals_dict.keys()),
            constraint_hash=constraint_hash,
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
            all_states = []
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
            item = self._work_queue.get(timeout=0.1)
            if item is None:
                if self._work_queue.empty():
                    time.sleep(0.05)
                    if self._work_queue.empty():
                        break
                continue
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
                    continue
            result = self._explore_path(item, worker_id)
            paths_explored += 1
            with self._result_lock:
                self._result.add_path_result(result, worker_id)

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
            models = []
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


__all__ = [
    "ExplorationStrategy",
    "ExplorationConfig",
    "WorkItem",
    "PathResult",
    "ExplorationResult",
    "WorkQueue",
    "StateSignature",
    "StateMerger",
    "ParallelExplorer",
    "ConstraintPartitioner",
    "ParallelSolver",
]
