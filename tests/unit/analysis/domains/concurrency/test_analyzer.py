import time

from pysymex.analysis.domains.concurrency import (
    ConcurrencyIssueKind,
    MemoryOperation,
    OperationKind,
    ThreadState,
)
from pysymex.analysis.domains.concurrency.analyzer import ConcurrencyAnalyzer


class TestConcurrencyAnalyzer:
    """Test suite for pysymex.analysis.domains.concurrency.analyzer.ConcurrencyAnalyzer."""

    def test_reset(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        assert len(analyzer.get_thread_operations()) == 1
        analyzer.reset()
        assert len(analyzer.get_thread_operations()) == 0

    def test_create_thread(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        t = analyzer.create_thread("t1", is_main=True)
        assert t.thread_id == "t1"
        assert t.state == ThreadState.RUNNING

    def test_start_thread(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("parent", is_main=True)
        analyzer.create_thread("child")
        analyzer.start_thread("child", "parent")
        t = analyzer.get_thread("child")
        assert t is not None
        assert t.state == ThreadState.RUNNING

    def test_join_thread(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("parent")
        analyzer.create_thread("child")
        analyzer.start_thread("child", "parent")
        issue = analyzer.join_thread("child", "parent")
        child = analyzer.get_thread("child")
        assert issue is None
        assert child is not None
        assert child.state == ThreadState.TERMINATED

    def test_record_read(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        op_id = analyzer.record_read("t1", "x")
        ops = analyzer.get_thread_operations()["t1"]
        assert op_id in ops

    def test_record_write(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        op_id = analyzer.record_write("t1", "x", 42)
        ops = analyzer.get_thread_operations()["t1"]
        assert op_id in ops

    def test_record_atomic_rmw(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        op_id = analyzer.record_atomic_rmw("t1", "x", 43)
        assert op_id in analyzer.get_thread_operations()["t1"]

    def test_acquire_lock(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        issue = analyzer.acquire_lock("t1", "L1")
        assert issue is None

        issue2 = analyzer.acquire_lock("t1", "L1")
        assert issue2 is not None
        assert issue2.kind == ConcurrencyIssueKind.DEADLOCK

    def test_release_lock(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        analyzer.acquire_lock("t1", "L1")
        issue = analyzer.release_lock("t1", "L1")
        assert issue is None

        issue2 = analyzer.release_lock("t1", "L2")
        assert issue2 is not None
        assert issue2.kind == ConcurrencyIssueKind.LOCK_NOT_HELD

    def test_detect_data_races(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        analyzer.create_thread("t2")
        analyzer.record_write("t1", "x")
        analyzer.record_write("t2", "x")
        races = analyzer.detect_data_races()
        assert len(races) >= 1
        assert races[0].kind == ConcurrencyIssueKind.DATA_RACE

    def test_detect_deadlocks(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        analyzer.create_thread("t2")
        analyzer.acquire_lock("t1", "L1")
        analyzer.acquire_lock("t1", "L2")
        analyzer.acquire_lock("t2", "L2")
        analyzer.acquire_lock("t2", "L1")
        issues = analyzer.detect_deadlocks()
        assert len(issues) >= 1
        assert issues[0].kind == ConcurrencyIssueKind.DEADLOCK

    def test_detect_deadlocks_keeps_single_thread_cycle_potential(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        analyzer.acquire_lock("t1", "L1")
        analyzer.acquire_lock("t1", "L2")
        analyzer.release_lock("t1", "L2")
        analyzer.release_lock("t1", "L1")
        analyzer.acquire_lock("t1", "L2")
        analyzer.acquire_lock("t1", "L1")

        issues = analyzer.detect_deadlocks()

        assert len(issues) >= 1
        assert issues[0].kind == ConcurrencyIssueKind.POTENTIAL_DEADLOCK

    def test_detect_deadlocks_reports_solver_unknown_as_inconclusive(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        analyzer.create_thread("t2")
        analyzer.acquire_lock("t1", "L1")
        analyzer.acquire_lock("t1", "L2")
        analyzer.acquire_lock("t2", "L2")
        analyzer.acquire_lock("t2", "L1")
        analyzer.solver.set_deadline(time.perf_counter() - 1.0)

        issues = analyzer.detect_deadlocks()

        assert len(issues) >= 1
        assert issues[0].kind == ConcurrencyIssueKind.POTENTIAL_DEADLOCK
        assert issues[0].severity == "warning"
        assert "Inconclusive" in issues[0].message

    def test_detect_await_cycles(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        graph = {"coroA": "coroB", "coroB": "coroA"}
        cycles = analyzer.detect_await_cycles(graph)
        assert len(cycles) > 0

    def test_detect_atomicity_violations(self) -> None:
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

    def test_get_thread(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        t = analyzer.create_thread("t1")
        assert analyzer.get_thread("t1") is t
        assert analyzer.get_thread("t2") is None

    def test_hb_graph(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        analyzer.record_read("t1", "x")
        assert len(analyzer.hb_graph.operations) == 1

    def test_get_thread_operations(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        op = analyzer.record_read("t1", "x")
        assert analyzer.get_thread_operations() == {"t1": [op]}

    def test_get_all_issues(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        analyzer.create_thread("t1")
        analyzer.create_thread("t2")
        analyzer.record_write("t1", "x")
        analyzer.record_write("t2", "x")
        issues = analyzer.get_all_issues()
        assert len(issues) > 0

    def test_get_summary(self) -> None:
        analyzer = ConcurrencyAnalyzer()
        summary = analyzer.get_summary()
        assert summary["threads"] == 0
        assert summary["total_operations"] == 0
