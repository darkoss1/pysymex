"""Tests for concurrency module.

Tests the Z3-based concurrency analysis including:
- Thread interleaving model
- Data race detection
- Deadlock analysis
- Lock operations
- Happens-before relationships
"""

import pytest

from pysymex.analysis.concurrency import (
    ConcurrencyAnalyzer,
    ConcurrencyIssue,
    ConcurrencyIssueKind,
    HappensBeforeGraph,
    MemoryOperation,
    MemoryOrder,
    OperationKind,
    Thread,
    ThreadState,
)

# =============================================================================
# MemoryOrder Tests
# =============================================================================


class TestMemoryOrder:
    """Tests for MemoryOrder enum."""

    def test_memory_orders(self):
        """Test memory order values exist."""
        assert MemoryOrder.RELAXED
        assert MemoryOrder.ACQUIRE
        assert MemoryOrder.RELEASE
        assert MemoryOrder.ACQ_REL
        assert MemoryOrder.SEQ_CST


# =============================================================================
# OperationKind Tests
# =============================================================================


class TestOperationKind:
    """Tests for OperationKind enum."""

    def test_basic_operations(self):
        """Test basic operation kinds exist."""
        assert OperationKind.READ
        assert OperationKind.WRITE
        assert OperationKind.READ_MODIFY_WRITE

    def test_synchronization_operations(self):
        """Test synchronization operation kinds exist."""
        assert OperationKind.LOCK_ACQUIRE
        assert OperationKind.LOCK_RELEASE
        assert OperationKind.FENCE

    def test_thread_operations(self):
        """Test thread operation kinds exist."""
        assert OperationKind.THREAD_CREATE
        assert OperationKind.THREAD_JOIN
        assert OperationKind.BARRIER


# =============================================================================
# ThreadState Tests
# =============================================================================


class TestThreadState:
    """Tests for ThreadState enum."""

    def test_thread_states(self):
        """Test thread state values exist."""
        assert ThreadState.NOT_STARTED
        assert ThreadState.RUNNING
        assert ThreadState.BLOCKED
        assert ThreadState.WAITING
        assert ThreadState.TERMINATED


# =============================================================================
# MemoryOperation Tests
# =============================================================================


class TestMemoryOperation:
    """Tests for MemoryOperation class."""

    def test_operation_creation(self):
        """Test memory operation creation."""
        op = MemoryOperation(
            thread_id="main",
            operation=OperationKind.WRITE,
            address="x",
            value=42,
            order=MemoryOrder.SEQ_CST,
            line_number=10,
        )

        assert op.thread_id == "main"
        assert op.operation == OperationKind.WRITE
        assert op.address == "x"
        assert op.value == 42

    def test_is_write(self):
        """Test write detection."""
        write_op = MemoryOperation(
            thread_id="main",
            operation=OperationKind.WRITE,
            address="x",
        )
        read_op = MemoryOperation(
            thread_id="main",
            operation=OperationKind.READ,
            address="x",
        )
        rmw_op = MemoryOperation(
            thread_id="main",
            operation=OperationKind.READ_MODIFY_WRITE,
            address="x",
        )

        assert write_op.is_write() is True
        assert read_op.is_write() is False
        assert rmw_op.is_write() is True

    def test_is_read(self):
        """Test read detection."""
        write_op = MemoryOperation(
            thread_id="main",
            operation=OperationKind.WRITE,
            address="x",
        )
        read_op = MemoryOperation(
            thread_id="main",
            operation=OperationKind.READ,
            address="x",
        )
        rmw_op = MemoryOperation(
            thread_id="main",
            operation=OperationKind.READ_MODIFY_WRITE,
            address="x",
        )

        assert write_op.is_read() is False
        assert read_op.is_read() is True
        assert rmw_op.is_read() is True

    def test_conflicts_with_same_address_different_thread(self):
        """Test conflict detection for same address, different threads."""
        op1 = MemoryOperation(
            thread_id="t1",
            operation=OperationKind.WRITE,
            address="x",
        )
        op2 = MemoryOperation(
            thread_id="t2",
            operation=OperationKind.READ,
            address="x",
        )

        assert op1.conflicts_with(op2) is True

    def test_no_conflict_same_thread(self):
        """Test no conflict for same thread."""
        op1 = MemoryOperation(
            thread_id="t1",
            operation=OperationKind.WRITE,
            address="x",
        )
        op2 = MemoryOperation(
            thread_id="t1",
            operation=OperationKind.READ,
            address="x",
        )

        assert op1.conflicts_with(op2) is False

    def test_no_conflict_different_address(self):
        """Test no conflict for different addresses."""
        op1 = MemoryOperation(
            thread_id="t1",
            operation=OperationKind.WRITE,
            address="x",
        )
        op2 = MemoryOperation(
            thread_id="t2",
            operation=OperationKind.WRITE,
            address="y",
        )

        assert op1.conflicts_with(op2) is False

    def test_no_conflict_both_reads(self):
        """Test no conflict when both are reads."""
        op1 = MemoryOperation(
            thread_id="t1",
            operation=OperationKind.READ,
            address="x",
        )
        op2 = MemoryOperation(
            thread_id="t2",
            operation=OperationKind.READ,
            address="x",
        )

        assert op1.conflicts_with(op2) is False


# =============================================================================
# Thread Tests
# =============================================================================


class TestThread:
    """Tests for Thread class."""

    def test_thread_creation(self):
        """Test thread creation."""
        thread = Thread(thread_id="main")

        assert thread.thread_id == "main"
        assert thread.state == ThreadState.NOT_STARTED
        assert len(thread.operations) == 0
        assert len(thread.held_locks) == 0

    def test_add_operation(self):
        """Test adding operations to thread."""
        thread = Thread(thread_id="main")
        op = MemoryOperation(
            thread_id="main",
            operation=OperationKind.WRITE,
            address="x",
        )

        thread.add_operation(op)

        assert len(thread.operations) == 1
        assert thread.operations[0] == op


# =============================================================================
# HappensBeforeGraph Tests
# =============================================================================


class TestHappensBeforeGraph:
    """Tests for HappensBeforeGraph class."""

    @pytest.fixture
    def hb_graph(self):
        return HappensBeforeGraph()

    def test_graph_creation(self, hb_graph):
        """Test graph creation."""
        assert len(hb_graph._operations) == 0
        assert len(hb_graph._edges) == 0

    def test_add_operation(self, hb_graph):
        """Test adding operation to graph."""
        op = MemoryOperation(
            thread_id="main",
            operation=OperationKind.WRITE,
            address="x",
        )

        op_id = hb_graph.add_operation(op)

        assert op_id == 0
        assert hb_graph.get_operation(op_id) == op

    def test_add_edge(self, hb_graph):
        """Test adding edge to graph."""
        op1 = MemoryOperation(thread_id="main", operation=OperationKind.WRITE, address="x")
        op2 = MemoryOperation(thread_id="main", operation=OperationKind.READ, address="x")

        id1 = hb_graph.add_operation(op1)
        id2 = hb_graph.add_operation(op2)
        hb_graph.add_edge(id1, id2)

        assert (id1, id2) in hb_graph._edges

    def test_add_program_order(self, hb_graph):
        """Test adding program order edges."""
        op1 = MemoryOperation(thread_id="t1", operation=OperationKind.WRITE, address="x")
        op2 = MemoryOperation(thread_id="t1", operation=OperationKind.WRITE, address="y")
        op3 = MemoryOperation(thread_id="t1", operation=OperationKind.WRITE, address="z")

        id1 = hb_graph.add_operation(op1)
        id2 = hb_graph.add_operation(op2)
        id3 = hb_graph.add_operation(op3)

        hb_graph.add_program_order("t1", [id1, id2, id3])

        assert (id1, id2) in hb_graph._edges
        assert (id2, id3) in hb_graph._edges

    def test_happens_before_direct(self, hb_graph):
        """Test direct happens-before relationship."""
        op1 = MemoryOperation(thread_id="main", operation=OperationKind.WRITE, address="x")
        op2 = MemoryOperation(thread_id="main", operation=OperationKind.READ, address="x")

        id1 = hb_graph.add_operation(op1)
        id2 = hb_graph.add_operation(op2)
        hb_graph.add_edge(id1, id2)

        assert hb_graph.happens_before(id1, id2) is True
        assert hb_graph.happens_before(id2, id1) is False

    def test_happens_before_transitive(self, hb_graph):
        """Test transitive happens-before relationship."""
        op1 = MemoryOperation(thread_id="main", operation=OperationKind.WRITE, address="x")
        op2 = MemoryOperation(thread_id="main", operation=OperationKind.WRITE, address="y")
        op3 = MemoryOperation(thread_id="main", operation=OperationKind.WRITE, address="z")

        id1 = hb_graph.add_operation(op1)
        id2 = hb_graph.add_operation(op2)
        id3 = hb_graph.add_operation(op3)

        hb_graph.add_edge(id1, id2)
        hb_graph.add_edge(id2, id3)

        # Transitive: id1 -> id2 -> id3
        assert hb_graph.happens_before(id1, id3) is True

    def test_are_concurrent_no_relation(self, hb_graph):
        """Test concurrent operations (no happens-before)."""
        op1 = MemoryOperation(thread_id="t1", operation=OperationKind.WRITE, address="x")
        op2 = MemoryOperation(thread_id="t2", operation=OperationKind.WRITE, address="x")

        id1 = hb_graph.add_operation(op1)
        id2 = hb_graph.add_operation(op2)
        # No edges - operations are concurrent

        assert hb_graph.are_concurrent(id1, id2) is True

    def test_are_concurrent_with_order(self, hb_graph):
        """Test non-concurrent operations (have happens-before)."""
        op1 = MemoryOperation(thread_id="main", operation=OperationKind.WRITE, address="x")
        op2 = MemoryOperation(thread_id="main", operation=OperationKind.READ, address="x")

        id1 = hb_graph.add_operation(op1)
        id2 = hb_graph.add_operation(op2)
        hb_graph.add_edge(id1, id2)

        assert hb_graph.are_concurrent(id1, id2) is False

    def test_add_synchronizes_with(self, hb_graph):
        """Test adding synchronizes-with edge."""
        release_op = MemoryOperation(
            thread_id="t1",
            operation=OperationKind.LOCK_RELEASE,
            address="lock",
        )
        acquire_op = MemoryOperation(
            thread_id="t2",
            operation=OperationKind.LOCK_ACQUIRE,
            address="lock",
        )

        release_id = hb_graph.add_operation(release_op)
        acquire_id = hb_graph.add_operation(acquire_op)

        hb_graph.add_synchronizes_with(release_id, acquire_id)

        assert hb_graph.happens_before(release_id, acquire_id) is True


# =============================================================================
# ConcurrencyAnalyzer Tests
# =============================================================================


class TestConcurrencyAnalyzer:
    """Tests for ConcurrencyAnalyzer class."""

    @pytest.fixture
    def analyzer(self):
        return ConcurrencyAnalyzer()

    def test_analyzer_creation(self, analyzer):
        """Test analyzer initialization."""
        assert analyzer.timeout_ms == 10000

    def test_create_thread(self, analyzer):
        """Test thread creation."""
        thread = analyzer.create_thread("main", is_main=True)

        assert thread.thread_id == "main"
        assert thread.state == ThreadState.RUNNING

    def test_create_non_main_thread(self, analyzer):
        """Test non-main thread creation."""
        thread = analyzer.create_thread("worker")

        assert thread.thread_id == "worker"
        assert thread.state == ThreadState.NOT_STARTED

    def test_start_thread(self, analyzer):
        """Test starting a thread."""
        analyzer.create_thread("main", is_main=True)
        analyzer.create_thread("worker")

        issue = analyzer.start_thread("worker", "main")

        assert issue is None

    def test_join_thread_success(self, analyzer):
        """Test joining a started thread."""
        analyzer.create_thread("main", is_main=True)
        thread = analyzer.create_thread("worker")
        thread.state = ThreadState.RUNNING  # Simulate started

        issue = analyzer.join_thread("worker", "main")

        assert issue is None
        assert thread.state == ThreadState.TERMINATED

    def test_join_thread_not_started(self, analyzer):
        """Test joining a non-started thread."""
        analyzer.create_thread("main", is_main=True)
        analyzer.create_thread("worker")  # Not started

        issue = analyzer.join_thread("worker", "main")

        assert issue is not None
        assert issue.kind == ConcurrencyIssueKind.JOIN_WITHOUT_START

    def test_join_thread_unknown_joiner(self, analyzer):
        """Joining from an unregistered thread should produce an issue, not crash."""
        thread = analyzer.create_thread("worker")
        thread.state = ThreadState.RUNNING

        issue = analyzer.join_thread("worker", "observer")

        assert issue is not None
        assert issue.kind == ConcurrencyIssueKind.JOIN_WITHOUT_START

    def test_record_read(self, analyzer):
        """Test recording read operation."""
        analyzer.create_thread("main", is_main=True)

        op_id = analyzer.record_read("main", "x", line_number=10)

        assert op_id >= 0
        assert "x" in analyzer._shared_variables

    def test_record_write(self, analyzer):
        """Test recording write operation."""
        analyzer.create_thread("main", is_main=True)

        op_id = analyzer.record_write("main", "x", value=42, line_number=10)

        assert op_id >= 0
        assert "x" in analyzer._shared_variables

    def test_record_atomic_rmw(self, analyzer):
        """Test recording atomic RMW operation."""
        analyzer.create_thread("main", is_main=True)

        op_id = analyzer.record_atomic_rmw("main", "counter", value=1)

        assert op_id >= 0

    def test_acquire_lock(self, analyzer):
        """Test lock acquisition."""
        analyzer.create_thread("main", is_main=True)

        issue = analyzer.acquire_lock("main", "mutex", line_number=10)

        assert issue is None
        assert analyzer._locks["mutex"] == "main"

    def test_release_lock(self, analyzer):
        """Test lock release."""
        analyzer.create_thread("main", is_main=True)
        analyzer.acquire_lock("main", "mutex")

        issue = analyzer.release_lock("main", "mutex")

        assert issue is None
        assert analyzer._locks["mutex"] is None

    def test_release_lock_not_held(self, analyzer):
        """Test releasing lock not held."""
        analyzer.create_thread("main", is_main=True)

        issue = analyzer.release_lock("main", "mutex")

        assert issue is not None
        assert issue.kind == ConcurrencyIssueKind.LOCK_NOT_HELD

    def test_double_acquire_same_thread(self, analyzer):
        """Test double acquire by same thread (deadlock)."""
        analyzer.create_thread("main", is_main=True)
        analyzer.acquire_lock("main", "mutex")

        issue = analyzer.acquire_lock("main", "mutex")

        assert issue is not None
        assert issue.kind == ConcurrencyIssueKind.DEADLOCK

    def test_detect_data_races(self, analyzer):
        """Test data race detection."""
        analyzer.create_thread("t1", is_main=True)
        analyzer.create_thread("t2")

        # Both threads access x without synchronization
        analyzer.record_write("t1", "x", value=1)
        analyzer.record_read("t2", "x")

        races = analyzer.detect_data_races()

        # Should detect potential data race
        assert len(races) > 0
        assert races[0].kind == ConcurrencyIssueKind.DATA_RACE

    def test_no_data_race_same_thread(self, analyzer):
        """Test no data race for same thread operations."""
        analyzer.create_thread("main", is_main=True)

        # Same thread - program order
        analyzer.record_write("main", "x", value=1)
        analyzer.record_read("main", "x")

        # Add program order
        analyzer._hb_graph.add_program_order("main", analyzer._thread_op_ids["main"])

        races = analyzer.detect_data_races()

        # No data race within same thread (has happens-before)
        assert len(races) == 0

    def test_analyzer_reset(self, analyzer):
        """Test analyzer reset."""
        analyzer.create_thread("main", is_main=True)
        analyzer.record_write("main", "x", value=1)

        analyzer.reset()

        assert len(analyzer._threads) == 0
        assert len(analyzer._shared_variables) == 0


# =============================================================================
# ConcurrencyIssue Tests
# =============================================================================


class TestConcurrencyIssue:
    """Tests for ConcurrencyIssue class."""

    def test_issue_creation(self):
        """Test issue creation."""
        issue = ConcurrencyIssue(
            kind=ConcurrencyIssueKind.DATA_RACE,
            message="Race on variable x",
            threads_involved=["t1", "t2"],
            shared_resource="x",
            line_number=42,
        )

        assert issue.kind == ConcurrencyIssueKind.DATA_RACE
        assert "t1" in issue.threads_involved
        assert issue.shared_resource == "x"

    def test_issue_format(self):
        """Test issue formatting."""
        issue = ConcurrencyIssue(
            kind=ConcurrencyIssueKind.DATA_RACE,
            message="Race on variable x",
            threads_involved=["t1", "t2"],
            shared_resource="x",
            line_number=42,
        )

        formatted = issue.format()
        assert "DATA_RACE" in formatted
        assert "t1" in formatted
        assert "t2" in formatted
        assert "42" in formatted


# =============================================================================
# ConcurrencyIssueKind Tests
# =============================================================================


class TestConcurrencyIssueKind:
    """Tests for ConcurrencyIssueKind enum."""

    def test_race_issues(self):
        """Test race-related issue kinds exist."""
        assert ConcurrencyIssueKind.DATA_RACE
        assert ConcurrencyIssueKind.RACE_CONDITION

    def test_deadlock_issues(self):
        """Test deadlock-related issue kinds exist."""
        assert ConcurrencyIssueKind.DEADLOCK
        assert ConcurrencyIssueKind.POTENTIAL_DEADLOCK
        assert ConcurrencyIssueKind.LIVELOCK

    def test_atomicity_issues(self):
        """Test atomicity-related issue kinds exist."""
        assert ConcurrencyIssueKind.ATOMICITY_VIOLATION
        assert ConcurrencyIssueKind.LOST_UPDATE

    def test_memory_order_issues(self):
        """Test memory order issue kinds exist."""
        assert ConcurrencyIssueKind.MEMORY_ORDER_VIOLATION
        assert ConcurrencyIssueKind.STALE_READ

    def test_lock_issues(self):
        """Test lock-related issue kinds exist."""
        assert ConcurrencyIssueKind.LOCK_NOT_HELD
        assert ConcurrencyIssueKind.WRONG_LOCK
