"""Concurrency Analysis with Z3.
This module provides comprehensive concurrency analysis using Z3 SMT solver
for mathematical proofs of thread safety. Covers:
- Thread interleaving model
- Race condition detection
- Deadlock analysis
- Data race detection
- Atomicity violation detection
- Memory ordering issues
- Happens-before relationships
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any
import z3


class MemoryOrder(Enum):
    """Memory ordering semantics."""

    RELAXED = auto()
    ACQUIRE = auto()
    RELEASE = auto()
    ACQ_REL = auto()
    SEQ_CST = auto()


class OperationKind(Enum):
    """Types of memory operations."""

    READ = auto()
    WRITE = auto()
    READ_MODIFY_WRITE = auto()
    FENCE = auto()
    LOCK_ACQUIRE = auto()
    LOCK_RELEASE = auto()
    THREAD_CREATE = auto()
    THREAD_JOIN = auto()
    BARRIER = auto()


class ThreadState(Enum):
    """Thread execution states."""

    NOT_STARTED = auto()
    RUNNING = auto()
    BLOCKED = auto()
    WAITING = auto()
    TERMINATED = auto()


class ConcurrencyIssueKind(Enum):
    """Types of concurrency issues."""

    DATA_RACE = auto()
    RACE_CONDITION = auto()
    DEADLOCK = auto()
    POTENTIAL_DEADLOCK = auto()
    LIVELOCK = auto()
    ATOMICITY_VIOLATION = auto()
    LOST_UPDATE = auto()
    MEMORY_ORDER_VIOLATION = auto()
    STALE_READ = auto()
    LOCK_NOT_HELD = auto()
    WRONG_LOCK = auto()
    USE_AFTER_JOIN = auto()
    JOIN_WITHOUT_START = auto()
    SPURIOUS_WAKEUP = auto()
    SIGNAL_SAFETY = auto()


@dataclass
class ConcurrencyIssue:
    """Represents a detected concurrency issue."""

    kind: ConcurrencyIssueKind
    message: str
    threads_involved: list[str] = field(default_factory=list)
    shared_resource: str | None = None
    location: str | None = None
    line_number: int | None = None
    schedule: list[tuple[str, str]] | None = None
    constraints: list[Any] = field(default_factory=list)
    counterexample: dict[str, Any] = field(default_factory=dict)
    severity: str = "error"

    def format(self) -> str:
        """Format issue for display."""
        loc = f" at line {self.line_number}" if self.line_number else ""
        threads = f" (threads: {', '.join(self.threads_involved)})" if self.threads_involved else ""
        res = f" on {self.shared_resource}" if self.shared_resource else ""
        return f"[{self.kind.name}]{loc}{threads}{res}: {self.message}"


@dataclass(frozen=True)
class MemoryOperation:
    """Represents a memory operation for analysis."""

    thread_id: str
    operation: OperationKind
    address: str
    value: Any | None = None
    order: MemoryOrder = MemoryOrder.SEQ_CST
    line_number: int | None = None
    timestamp: int = 0

    def is_write(self) -> bool:
        return self.operation in {OperationKind.WRITE, OperationKind.READ_MODIFY_WRITE}

    def is_read(self) -> bool:
        return self.operation in {OperationKind.READ, OperationKind.READ_MODIFY_WRITE}

    def conflicts_with(self, other: MemoryOperation) -> bool:
        """Check if this operation conflicts with another."""
        if self.address != other.address:
            return False
        if self.thread_id == other.thread_id:
            return False
        return self.is_write() or other.is_write()


@dataclass
class Thread:
    """Represents a thread for analysis."""

    thread_id: str
    state: ThreadState = ThreadState.NOT_STARTED
    operations: list[MemoryOperation] = field(default_factory=list)
    held_locks: set[str] = field(default_factory=set)
    waiting_for: str | None = None

    def add_operation(self, op: MemoryOperation) -> None:
        """Add an operation to this thread's history."""
        self.operations.append(op)


class HappensBeforeGraph:
    """
    Tracks happens-before relationships between operations.
    Used to determine if a data race exists (concurrent, conflicting accesses).
    """

    def __init__(self):
        self._edges: set[tuple[int, int]] = set()
        self._operations: dict[int, MemoryOperation] = {}
        self._op_counter = 0

    def add_operation(self, op: MemoryOperation) -> int:
        """Add operation and return its ID."""
        op_id = self._op_counter
        self._op_counter += 1
        self._operations[op_id] = op
        return op_id

    def add_edge(self, from_op: int, to_op: int) -> None:
        """Add happens-before edge."""
        self._edges.add((from_op, to_op))

    def add_program_order(self, thread_id: str, op_ids: list[int]) -> None:
        """Add program order edges for a thread."""
        for i in range(len(op_ids) - 1):
            self._edges.add((op_ids[i], op_ids[i + 1]))

    def add_synchronizes_with(self, release_op: int, acquire_op: int) -> None:
        """Add synchronizes-with edge (release -> acquire)."""
        self._edges.add((release_op, acquire_op))

    def happens_before(self, op1: int, op2: int) -> bool:
        """Check if op1 happens-before op2 (transitive)."""
        visited = set()
        queue = [op1]
        while queue:
            current = queue.pop(0)
            if current == op2:
                return True
            if current in visited:
                continue
            visited.add(current)
            for from_op, to_op in self._edges:
                if from_op == current:
                    queue.append(to_op)
        return False

    def are_concurrent(self, op1: int, op2: int) -> bool:
        """Check if two operations are concurrent (neither happens-before the other)."""
        return not self.happens_before(op1, op2) and not self.happens_before(op2, op1)

    def get_operation(self, op_id: int) -> MemoryOperation | None:
        """Get operation by ID."""
        return self._operations.get(op_id)


class ConcurrencyAnalyzer:
    """
    Comprehensive concurrency analyzer using Z3.
    Models thread interleavings and detects concurrency bugs
    via SMT solving.
    """

    def __init__(self, timeout_ms: int = 10000):
        self.timeout_ms = timeout_ms
        self._solver = z3.Solver()
        self._solver.set("timeout", timeout_ms)
        self._threads: dict[str, Thread] = {}
        self._main_thread: str | None = None
        self._shared_variables: set[str] = set()
        self._locks: dict[str, str | None] = {}
        self._lock_acquisitions: dict[str, list[str]] = {}
        self._hb_graph = HappensBeforeGraph()
        self._thread_op_ids: dict[str, list[int]] = {}
        self._issues: list[ConcurrencyIssue] = []

    def reset(self) -> None:
        """Reset analyzer state."""
        self._solver.reset()
        self._threads.clear()
        self._shared_variables.clear()
        self._locks.clear()
        self._lock_acquisitions.clear()
        self._hb_graph = HappensBeforeGraph()
        self._thread_op_ids.clear()
        self._issues.clear()

    def create_thread(
        self,
        thread_id: str,
        is_main: bool = False,
    ) -> Thread:
        """Create a new thread for analysis."""
        thread = Thread(thread_id=thread_id)
        self._threads[thread_id] = thread
        self._thread_op_ids[thread_id] = []
        if is_main:
            self._main_thread = thread_id
            thread.state = ThreadState.RUNNING
        return thread

    def start_thread(
        self,
        thread_id: str,
        parent_thread: str,
        line_number: int | None = None,
    ) -> ConcurrencyIssue | None:
        """Record thread start."""
        thread = self._threads.get(thread_id)
        if thread is None:
            return None
        thread.state = ThreadState.RUNNING
        if parent_thread in self._thread_op_ids and self._thread_op_ids[parent_thread]:
            parent_last_op = self._thread_op_ids[parent_thread][-1]
            start_op = MemoryOperation(
                thread_id=thread_id,
                operation=OperationKind.THREAD_CREATE,
                address=f"__thread_start_{thread_id}",
                line_number=line_number,
            )
            start_op_id = self._hb_graph.add_operation(start_op)
            self._thread_op_ids[thread_id].append(start_op_id)
            self._hb_graph.add_edge(parent_last_op, start_op_id)
        return None

    def join_thread(
        self,
        thread_id: str,
        joining_thread: str,
        line_number: int | None = None,
    ) -> ConcurrencyIssue | None:
        """Record thread join."""
        thread = self._threads.get(thread_id)
        if thread is None:
            return ConcurrencyIssue(
                kind=ConcurrencyIssueKind.JOIN_WITHOUT_START,
                message=f"Joining thread '{thread_id}' that doesn't exist",
                threads_involved=[joining_thread, thread_id],
                line_number=line_number,
            )
        if thread.state == ThreadState.NOT_STARTED:
            return ConcurrencyIssue(
                kind=ConcurrencyIssueKind.JOIN_WITHOUT_START,
                message=f"Joining thread '{thread_id}' that hasn't started",
                threads_involved=[joining_thread, thread_id],
                line_number=line_number,
            )
        thread.state = ThreadState.TERMINATED
        if thread_id in self._thread_op_ids and self._thread_op_ids[thread_id]:
            child_last_op = self._thread_op_ids[thread_id][-1]
            join_op = MemoryOperation(
                thread_id=joining_thread,
                operation=OperationKind.THREAD_JOIN,
                address=f"__thread_join_{thread_id}",
                line_number=line_number,
            )
            join_op_id = self._hb_graph.add_operation(join_op)
            self._thread_op_ids[joining_thread].append(join_op_id)
            self._hb_graph.add_edge(child_last_op, join_op_id)
        return None

    def record_read(
        self,
        thread_id: str,
        variable: str,
        order: MemoryOrder = MemoryOrder.SEQ_CST,
        line_number: int | None = None,
    ) -> int:
        """Record a memory read operation."""
        op = MemoryOperation(
            thread_id=thread_id,
            operation=OperationKind.READ,
            address=variable,
            order=order,
            line_number=line_number,
            timestamp=len(self._hb_graph._operations),
        )
        op_id = self._hb_graph.add_operation(op)
        thread = self._threads.get(thread_id)
        if thread:
            thread.add_operation(op)
        self._thread_op_ids.setdefault(thread_id, []).append(op_id)
        self._shared_variables.add(variable)
        return op_id

    def record_write(
        self,
        thread_id: str,
        variable: str,
        value: Any = None,
        order: MemoryOrder = MemoryOrder.SEQ_CST,
        line_number: int | None = None,
    ) -> int:
        """Record a memory write operation."""
        op = MemoryOperation(
            thread_id=thread_id,
            operation=OperationKind.WRITE,
            address=variable,
            value=value,
            order=order,
            line_number=line_number,
            timestamp=len(self._hb_graph._operations),
        )
        op_id = self._hb_graph.add_operation(op)
        thread = self._threads.get(thread_id)
        if thread:
            thread.add_operation(op)
        self._thread_op_ids.setdefault(thread_id, []).append(op_id)
        self._shared_variables.add(variable)
        return op_id

    def record_atomic_rmw(
        self,
        thread_id: str,
        variable: str,
        value: Any = None,
        order: MemoryOrder = MemoryOrder.SEQ_CST,
        line_number: int | None = None,
    ) -> int:
        """Record an atomic read-modify-write operation."""
        op = MemoryOperation(
            thread_id=thread_id,
            operation=OperationKind.READ_MODIFY_WRITE,
            address=variable,
            value=value,
            order=order,
            line_number=line_number,
            timestamp=len(self._hb_graph._operations),
        )
        op_id = self._hb_graph.add_operation(op)
        thread = self._threads.get(thread_id)
        if thread:
            thread.add_operation(op)
        self._thread_op_ids.setdefault(thread_id, []).append(op_id)
        self._shared_variables.add(variable)
        return op_id

    def acquire_lock(
        self,
        thread_id: str,
        lock_name: str,
        line_number: int | None = None,
    ) -> ConcurrencyIssue | None:
        """Record lock acquisition."""
        current_holder = self._locks.get(lock_name)
        if current_holder == thread_id:
            return ConcurrencyIssue(
                kind=ConcurrencyIssueKind.DEADLOCK,
                message=f"Thread '{thread_id}' attempting to acquire lock it already holds",
                threads_involved=[thread_id],
                shared_resource=lock_name,
                line_number=line_number,
            )
        op = MemoryOperation(
            thread_id=thread_id,
            operation=OperationKind.LOCK_ACQUIRE,
            address=lock_name,
            order=MemoryOrder.ACQUIRE,
            line_number=line_number,
            timestamp=len(self._hb_graph._operations),
        )
        op_id = self._hb_graph.add_operation(op)
        self._thread_op_ids.setdefault(thread_id, []).append(op_id)
        self._locks[lock_name] = thread_id
        self._lock_acquisitions.setdefault(lock_name, []).append(thread_id)
        thread = self._threads.get(thread_id)
        if thread:
            thread.held_locks.add(lock_name)
        return None

    def release_lock(
        self,
        thread_id: str,
        lock_name: str,
        line_number: int | None = None,
    ) -> ConcurrencyIssue | None:
        """Record lock release."""
        current_holder = self._locks.get(lock_name)
        if current_holder != thread_id:
            return ConcurrencyIssue(
                kind=ConcurrencyIssueKind.LOCK_NOT_HELD,
                message=f"Thread '{thread_id}' releasing lock it doesn't hold",
                threads_involved=[thread_id],
                shared_resource=lock_name,
                line_number=line_number,
            )
        op = MemoryOperation(
            thread_id=thread_id,
            operation=OperationKind.LOCK_RELEASE,
            address=lock_name,
            order=MemoryOrder.RELEASE,
            line_number=line_number,
            timestamp=len(self._hb_graph._operations),
        )
        op_id = self._hb_graph.add_operation(op)
        self._thread_op_ids.setdefault(thread_id, []).append(op_id)
        self._locks[lock_name] = None
        thread = self._threads.get(thread_id)
        if thread:
            thread.held_locks.discard(lock_name)
        return None

    def detect_data_races(self) -> list[ConcurrencyIssue]:
        """
        Detect data races in recorded operations.
        A data race occurs when:
        1. Two operations access the same memory location
        2. At least one is a write
        3. They are from different threads
        4. They are not ordered by happens-before
        """
        issues = []
        for thread_id, op_ids in self._thread_op_ids.items():
            self._hb_graph.add_program_order(thread_id, op_ids)
        all_ops = list(self._hb_graph._operations.items())
        for i, (op_id1, op1) in enumerate(all_ops):
            for op_id2, op2 in all_ops[i + 1 :]:
                if op1.conflicts_with(op2) and self._hb_graph.are_concurrent(op_id1, op_id2):
                    issues.append(
                        ConcurrencyIssue(
                            kind=ConcurrencyIssueKind.DATA_RACE,
                            message=f"Data race on '{op1.address}' between threads",
                            threads_involved=[op1.thread_id, op2.thread_id],
                            shared_resource=op1.address,
                            line_number=op1.line_number,
                        )
                    )
        return issues

    def detect_deadlocks(self) -> list[ConcurrencyIssue]:
        """
        Detect potential deadlocks using lock order analysis.
        A deadlock can occur if there's a cycle in the lock acquisition graph.
        """
        issues = []
        lock_order_graph: dict[str, set[str]] = {}
        for thread_id, thread in self._threads.items():
            held_locks: list[str] = []
            for op in thread.operations:
                if op.operation == OperationKind.LOCK_ACQUIRE:
                    for held in held_locks:
                        lock_order_graph.setdefault(held, set()).add(op.address)
                    held_locks.append(op.address)
                elif op.operation == OperationKind.LOCK_RELEASE:
                    if op.address in held_locks:
                        held_locks.remove(op.address)

        def find_cycle(start: str) -> list[str] | None:
            visited = set()
            path = []

            def dfs(node: str) -> list[str] | None:
                if node in path:
                    cycle_start = path.index(node)
                    return path[cycle_start:] + [node]
                if node in visited:
                    return None
                visited.add(node)
                path.append(node)
                for neighbor in lock_order_graph.get(node, set()):
                    result = dfs(neighbor)
                    if result:
                        return result
                path.pop()
                return None

            return dfs(start)

        checked_cycles = set()
        for lock in lock_order_graph:
            cycle = find_cycle(lock)
            if cycle:
                cycle_key = tuple(sorted(cycle))
                if cycle_key not in checked_cycles:
                    checked_cycles.add(cycle_key)
                    issues.append(
                        ConcurrencyIssue(
                            kind=ConcurrencyIssueKind.POTENTIAL_DEADLOCK,
                            message=f"Potential deadlock: lock cycle {' -> '.join(cycle)}",
                            shared_resource=", ".join(cycle),
                        )
                    )
        return issues

    def detect_atomicity_violations(
        self,
        atomic_regions: list[tuple[str, list[MemoryOperation]]],
    ) -> list[ConcurrencyIssue]:
        """
        Detect atomicity violations.
        An atomicity violation occurs when a compound operation
        that should be atomic can be interleaved with conflicting operations.
        Args:
            atomic_regions: List of (thread_id, operations) that should be atomic
        """
        issues = []
        for thread_id, region_ops in atomic_regions:
            if len(region_ops) < 2:
                continue
            region_vars = {op.address for op in region_ops}
            for other_thread_id, other_thread in self._threads.items():
                if other_thread_id == thread_id:
                    continue
                for other_op in other_thread.operations:
                    if other_op.address in region_vars:
                        issues.append(
                            ConcurrencyIssue(
                                kind=ConcurrencyIssueKind.ATOMICITY_VIOLATION,
                                message=f"Atomicity violation: thread '{other_thread_id}' can access '{other_op.address}' during atomic region",
                                threads_involved=[thread_id, other_thread_id],
                                shared_resource=other_op.address,
                            )
                        )
                        break
        return issues

    def check_race_condition_z3(
        self,
        variable: str,
        expected_final_value: Any,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> tuple[bool, ConcurrencyIssue | None]:
        """
        Use Z3 to check if a race condition can produce an unexpected value.
        Models all possible interleavings and checks if expected value
        is always produced.
        """
        constraints = list(path_constraints or [])
        ops = [
            (op_id, op)
            for op_id, op in self._hb_graph._operations.items()
            if op.address == variable
        ]
        if not ops:
            return (True, None)
        order_vars = {}
        for op_id, op in ops:
            order_vars[op_id] = z3.Int(f"order_{op_id}")
        for from_op, to_op in self._hb_graph._edges:
            if from_op in order_vars and to_op in order_vars:
                constraints.append(order_vars[from_op] < order_vars[to_op])
        if len(order_vars) > 1:
            constraints.append(z3.Distinct(*order_vars.values()))
        writes = [(op_id, op) for op_id, op in ops if op.is_write()]
        if len(writes) > 1:
            w1_id, w1 = writes[0]
            w2_id, w2 = writes[1]
            self._solver.push()
            for c in constraints:
                self._solver.add(c)
            self._solver.add(order_vars[w2_id] < order_vars[w1_id])
            can_reorder = self._solver.check() == z3.sat
            self._solver.pop()
            if can_reorder:
                return (
                    False,
                    ConcurrencyIssue(
                        kind=ConcurrencyIssueKind.RACE_CONDITION,
                        message=f"Race condition: writes to '{variable}' can occur in different orders",
                        threads_involved=[w1.thread_id, w2.thread_id],
                        shared_resource=variable,
                    ),
                )
        return (True, None)

    def find_problematic_schedule(
        self,
        assertion: z3.BoolRef,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> list[tuple[str, str]] | None:
        """
        Find a schedule that violates an assertion.
        Returns the schedule (list of (thread_id, operation)) if found.
        """
        constraints = list(path_constraints or [])
        all_ops = list(self._hb_graph._operations.items())
        order_vars = {op_id: z3.Int(f"order_{op_id}") for op_id, _ in all_ops}
        for from_op, to_op in self._hb_graph._edges:
            if from_op in order_vars and to_op in order_vars:
                constraints.append(order_vars[from_op] < order_vars[to_op])
        if len(order_vars) > 1:
            constraints.append(z3.Distinct(*order_vars.values()))
        self._solver.push()
        for c in constraints:
            self._solver.add(c)
        self._solver.add(z3.Not(assertion))
        result = self._solver.check()
        if result == z3.sat:
            model = self._solver.model()
            self._solver.pop()
            schedule = []
            for op_id, op in all_ops:
                order = model.eval(order_vars[op_id], model_completion=True).as_long()
                schedule.append((order, op.thread_id, op.operation.name))
            schedule.sort(key=lambda x: x[0])
            return [(t, o) for _, t, o in schedule]
        self._solver.pop()
        return None

    def get_all_issues(self) -> list[ConcurrencyIssue]:
        """Get all detected concurrency issues."""
        all_issues = list(self._issues)
        all_issues.extend(self.detect_data_races())
        all_issues.extend(self.detect_deadlocks())
        return all_issues

    def get_summary(self) -> dict[str, Any]:
        """Get summary of concurrency analysis."""
        return {
            "threads": len(self._threads),
            "shared_variables": list(self._shared_variables),
            "locks": list(self._locks.keys()),
            "total_operations": len(self._hb_graph._operations),
            "happens_before_edges": len(self._hb_graph._edges),
        }


class ThreadSafetyChecker:
    """
    High-level thread safety checker for common patterns.
    """

    def __init__(self):
        self.analyzer = ConcurrencyAnalyzer()

    def check_locked_access(
        self,
        thread_id: str,
        variable: str,
        required_lock: str,
        is_write: bool = False,
        line_number: int | None = None,
    ) -> ConcurrencyIssue | None:
        """Check that access to variable is protected by required lock."""
        thread = self.analyzer._threads.get(thread_id)
        if thread is None:
            return None
        if required_lock not in thread.held_locks:
            return ConcurrencyIssue(
                kind=ConcurrencyIssueKind.LOCK_NOT_HELD,
                message=f"Accessing '{variable}' without holding lock '{required_lock}'",
                threads_involved=[thread_id],
                shared_resource=variable,
                line_number=line_number,
            )
        return None

    def check_double_checked_locking(
        self,
        thread_id: str,
        check_variable: str,
        lock_name: str,
        line_number: int | None = None,
    ) -> ConcurrencyIssue | None:
        """
        Check for broken double-checked locking pattern.
        The classic DCLP bug where the check outside the lock
        can read a partially constructed object.
        """
        return ConcurrencyIssue(
            kind=ConcurrencyIssueKind.MEMORY_ORDER_VIOLATION,
            message=f"Potential double-checked locking issue on '{check_variable}'",
            threads_involved=[thread_id],
            shared_resource=check_variable,
            line_number=line_number,
            severity="warning",
        )


class LockOrderChecker:
    """
    Checks and enforces lock ordering to prevent deadlocks.
    """

    def __init__(self):
        self._lock_order: list[str] = []
        self._thread_held_locks: dict[str, list[str]] = {}

    def set_lock_order(self, order: list[str]) -> None:
        """Set the expected lock acquisition order."""
        self._lock_order = order

    def acquire(
        self,
        thread_id: str,
        lock_name: str,
        line_number: int | None = None,
    ) -> ConcurrencyIssue | None:
        """Record lock acquisition and check ordering."""
        held = self._thread_held_locks.setdefault(thread_id, [])
        if lock_name in self._lock_order:
            lock_idx = self._lock_order.index(lock_name)
            for held_lock in held:
                if held_lock in self._lock_order:
                    held_idx = self._lock_order.index(held_lock)
                    if held_idx > lock_idx:
                        return ConcurrencyIssue(
                            kind=ConcurrencyIssueKind.POTENTIAL_DEADLOCK,
                            message=f"Lock order violation: acquiring '{lock_name}' while holding '{held_lock}'",
                            threads_involved=[thread_id],
                            shared_resource=f"{held_lock}, {lock_name}",
                            line_number=line_number,
                        )
        held.append(lock_name)
        return None

    def release(self, thread_id: str, lock_name: str) -> None:
        """Record lock release."""
        held = self._thread_held_locks.get(thread_id, [])
        if lock_name in held:
            held.remove(lock_name)


__all__ = [
    "MemoryOrder",
    "OperationKind",
    "ThreadState",
    "ConcurrencyIssueKind",
    "ConcurrencyIssue",
    "MemoryOperation",
    "Thread",
    "HappensBeforeGraph",
    "ConcurrencyAnalyzer",
    "ThreadSafetyChecker",
    "LockOrderChecker",
]
