import pytest
import z3
from pysymex.analysis.concurrency.core import (
    ConcurrencyAnalyzer,
    ThreadSafetyChecker,
    LockOrderChecker,
)
from pysymex.analysis.concurrency import (
    ConcurrencyIssue,
    ConcurrencyIssueKind,
    ThreadState,
    OperationKind,
    MemoryOperation,
)


class TestConcurrencyAnalyzer:
    """Test suite for pysymex.analysis.concurrency.core.ConcurrencyAnalyzer."""

    def test_reset(self) -> None:
        """Test reset behavior."""
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        assert len(analyzer.get_thread_operations()) == 1
        analyzer.reset()
        assert len(analyzer.get_thread_operations()) == 0

    def test_create_thread(self) -> None:
        """Test create_thread behavior."""
        analyzer = ConcurrencyAnalyzer()
        t = analyzer.create_thread("t1", is_main=True)
        assert t.thread_id == "t1"
        assert t.state == ThreadState.RUNNING

    def test_start_thread(self) -> None:
        """Test start_thread behavior."""
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("parent", is_main=True)
        analyzer.create_thread("child")
        analyzer.start_thread("child", "parent")
        t = analyzer.get_thread("child")
        assert t is not None
        assert t.state == ThreadState.RUNNING

    def test_join_thread(self) -> None:
        """Test join_thread behavior."""
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("parent")
        analyzer.create_thread("child")
        analyzer.start_thread("child", "parent")
        issue = analyzer.join_thread("child", "parent")
        assert issue is None
        assert analyzer.get_thread("child").state == ThreadState.TERMINATED

    def test_record_read(self) -> None:
        """Test record_read behavior."""
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        op_id = analyzer.record_read("t1", "x")
        ops = analyzer.get_thread_operations()["t1"]
        assert op_id in ops

    def test_record_write(self) -> None:
        """Test record_write behavior."""
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        op_id = analyzer.record_write("t1", "x", 42)
        ops = analyzer.get_thread_operations()["t1"]
        assert op_id in ops

    def test_record_atomic_rmw(self) -> None:
        """Test record_atomic_rmw behavior."""
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        op_id = analyzer.record_atomic_rmw("t1", "x", 43)
        assert op_id in analyzer.get_thread_operations()["t1"]

    def test_acquire_lock(self) -> None:
        """Test acquire_lock behavior."""
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        issue = analyzer.acquire_lock("t1", "L1")
        assert issue is None

        issue2 = analyzer.acquire_lock("t1", "L1")
        assert issue2 is not None
        assert issue2.kind == ConcurrencyIssueKind.DEADLOCK

    def test_release_lock(self) -> None:
        """Test release_lock behavior."""
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        analyzer.acquire_lock("t1", "L1")
        issue = analyzer.release_lock("t1", "L1")
        assert issue is None

        issue2 = analyzer.release_lock("t1", "L2")
        assert issue2 is not None
        assert issue2.kind == ConcurrencyIssueKind.LOCK_NOT_HELD

    def test_detect_data_races(self) -> None:
        """Test detect_data_races behavior."""
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        analyzer.create_thread("t2")
        analyzer.record_write("t1", "x")
        analyzer.record_write("t2", "x")
        races = analyzer.detect_data_races()
        assert len(races) >= 1
        assert races[0].kind == ConcurrencyIssueKind.DATA_RACE

    def test_detect_deadlocks(self) -> None:
        """Test detect_deadlocks behavior."""
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        analyzer.create_thread("t2")
        analyzer.acquire_lock("t1", "L1")
        analyzer.acquire_lock("t1", "L2")
        analyzer.acquire_lock("t2", "L2")
        analyzer.acquire_lock("t2", "L1")
        issues = analyzer.detect_deadlocks()
        assert len(issues) >= 1

    def test_detect_await_cycles(self) -> None:
        """Test detect_await_cycles behavior."""
        analyzer = ConcurrencyAnalyzer()
        graph = {"coroA": "coroB", "coroB": "coroA"}
        cycles = analyzer.detect_await_cycles(graph)
        assert len(cycles) > 0

    def test_detect_atomicity_violations(self) -> None:
        """Test detect_atomicity_violations behavior."""
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t2")
        analyzer.record_write("t2", "x")

        ops = [
            MemoryOperation("t1", OperationKind.READ, "x"),
            MemoryOperation("t1", OperationKind.WRITE, "x"),
        ]
        violations = analyzer.detect_atomicity_violations([("t1", ops)])
        assert len(violations) > 0
        assert violations[0].kind == ConcurrencyIssueKind.ATOMICITY_VIOLATION

    def test_check_race_condition_z3(self) -> None:
        """Test check_race_condition_z3 behavior."""
        analyzer = ConcurrencyAnalyzer()
        ok, issue = analyzer.check_race_condition_z3("x", 42)
        assert ok is True
        assert issue is None

    def test_find_problematic_schedule(self) -> None:
        """Test find_problematic_schedule behavior."""
        analyzer = ConcurrencyAnalyzer()
        schedule = analyzer.find_problematic_schedule(z3.BoolVal(True))
        assert schedule is None

    def test_get_thread(self) -> None:
        """Test get_thread behavior."""
        analyzer = ConcurrencyAnalyzer()
        t = analyzer.create_thread("t1")
        assert analyzer.get_thread("t1") is t
        assert analyzer.get_thread("t2") is None

    def test_hb_graph(self) -> None:
        """Test hb_graph behavior."""
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        analyzer.record_read("t1", "x")
        assert len(analyzer.hb_graph.operations) == 1

    def test_get_thread_operations(self) -> None:
        """Test get_thread_operations behavior."""
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        op = analyzer.record_read("t1", "x")
        assert analyzer.get_thread_operations() == {"t1": [op]}

    def test_get_all_issues(self) -> None:
        """Test get_all_issues behavior."""
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        analyzer.create_thread("t2")
        analyzer.record_write("t1", "x")
        analyzer.record_write("t2", "x")
        issues = analyzer.get_all_issues()
        assert len(issues) > 0

    def test_get_summary(self) -> None:
        """Test get_summary behavior."""
        analyzer = ConcurrencyAnalyzer()
        summary = analyzer.get_summary()
        assert summary["threads"] == 0
        assert summary["total_operations"] == 0


class TestThreadSafetyChecker:
    """Test suite for pysymex.analysis.concurrency.core.ThreadSafetyChecker."""

    def test_check_locked_access(self) -> None:
        """Test check_locked_access behavior."""
        checker = ThreadSafetyChecker()
        checker.analyzer.create_thread("t1")
        issue = checker.check_locked_access("t1", "x", "L1")
        assert issue is not None
        assert issue.kind == ConcurrencyIssueKind.LOCK_NOT_HELD

    def test_check_double_checked_locking(self) -> None:
        """Test check_double_checked_locking behavior."""
        checker = ThreadSafetyChecker()
        issue = checker.check_double_checked_locking("t1", "x", "L1")
        assert issue is not None
        assert issue.kind == ConcurrencyIssueKind.MEMORY_ORDER_VIOLATION


class TestLockOrderChecker:
    """Test suite for pysymex.analysis.concurrency.core.LockOrderChecker."""

    def test_set_lock_order(self) -> None:
        """Test set_lock_order behavior."""
        checker = LockOrderChecker()
        checker.set_lock_order(["L1", "L2"])
        assert checker._lock_order == ["L1", "L2"]

    def test_acquire(self) -> None:
        """Test acquire behavior."""
        checker = LockOrderChecker()
        checker.set_lock_order(["L1", "L2"])
        issue = checker.acquire("t1", "L2")
        assert issue is None

        checker.acquire("t2", "L2")
        issue_bad = checker.acquire("t2", "L1")
        assert issue_bad is not None
        assert issue_bad.kind == ConcurrencyIssueKind.POTENTIAL_DEADLOCK

    def test_release(self) -> None:
        """Test release behavior."""
        checker = LockOrderChecker()
        checker.set_lock_order(["L1"])
        checker.acquire("t1", "L1")
        issue = checker.release("t1", "L1")
        assert issue is None

        issue_bad = checker.release("t2", "L1")
        assert issue_bad is None
