import pytest
import z3
from unittest.mock import Mock, patch
from pysymex.analysis.resources.lifecycle import (
    ResourceStateMachine,
    TrackedResource,
    ResourceLifecycleChecker,
    FileResourceChecker,
    LockResourceChecker,
)
from pysymex.analysis.resources.types import ResourceState, ResourceKind


class TestResourceStateMachine:
    """Test suite for pysymex.analysis.resources.lifecycle.ResourceStateMachine."""

    def test_can_transition(self) -> None:
        """Test can_transition behavior."""
        sm = ResourceStateMachine(ResourceKind.FILE)
        assert sm.can_transition(ResourceState.UNINITIALIZED, "open_read") is True
        assert sm.can_transition(ResourceState.UNINITIALIZED, "read") is False

    def test_get_transition(self) -> None:
        """Test get_transition behavior."""
        sm = ResourceStateMachine(ResourceKind.FILE)
        t = sm.get_transition(ResourceState.UNINITIALIZED, "open_read")
        assert t is not None
        assert t.to_state == ResourceState.FILE_OPEN_READ

    def test_is_final_state(self) -> None:
        """Test is_final_state behavior."""
        sm = ResourceStateMachine(ResourceKind.FILE)
        assert sm.is_final_state(ResourceState.FILE_CLOSED) is True
        assert sm.is_final_state(ResourceState.FILE_OPEN_READ) is False

    def test_initial_state(self) -> None:
        """Test initial_state behavior."""
        sm = ResourceStateMachine(ResourceKind.FILE)
        assert sm.initial_state == ResourceState.UNINITIALIZED


class TestTrackedResource:
    """Test suite for pysymex.analysis.resources.lifecycle.TrackedResource."""

    def test_record_action(self) -> None:
        """Test record_action behavior."""
        sm = ResourceStateMachine(ResourceKind.FILE)
        tr = TrackedResource("f", ResourceKind.FILE, ResourceState.UNINITIALIZED, sm)
        tr.record_action("open_read", ResourceState.FILE_OPEN_READ, 10)
        assert tr.state == ResourceState.FILE_OPEN_READ
        assert tr.last_action_at == 10
        assert len(tr.history) == 1


class TestResourceLifecycleChecker:
    """Test suite for pysymex.analysis.resources.lifecycle.ResourceLifecycleChecker."""

    def test_reset(self) -> None:
        """Test reset behavior."""
        c = ResourceLifecycleChecker()
        c.create_resource("f", ResourceKind.FILE)
        c.reset()
        assert c.get_resource("f") is None

    def test_create_resource(self) -> None:
        """Test create_resource behavior."""
        c = ResourceLifecycleChecker()
        r = c.create_resource("f", ResourceKind.FILE)
        assert r.name == "f"

    def test_get_resource(self) -> None:
        """Test get_resource behavior."""
        c = ResourceLifecycleChecker()
        c.create_resource("f", ResourceKind.FILE)
        assert c.get_resource("f") is not None

    def test_check_action(self) -> None:
        """Test check_action behavior."""
        c = ResourceLifecycleChecker()
        c.create_resource("f", ResourceKind.FILE)
        assert c.check_action("f", "read") is not None
        assert c.check_action("f", "open_read") is None

    def test_perform_action(self) -> None:
        """Test perform_action behavior."""
        c = ResourceLifecycleChecker()
        c.create_resource("f", ResourceKind.FILE)
        state, issue = c.perform_action("f", "open_read")
        assert state == ResourceState.FILE_OPEN_READ
        assert issue is None

    def test_check_leaks(self) -> None:
        """Test check_leaks behavior."""
        c = ResourceLifecycleChecker()
        c.create_resource("f", ResourceKind.FILE)
        c.perform_action("f", "open_read")
        issues = c.check_leaks()
        assert len(issues) == 1

        c.perform_action("f", "close")
        assert len(c.check_leaks()) == 0

    def test_check_potential_leak(self) -> None:
        """Test check_potential_leak behavior."""
        c = ResourceLifecycleChecker()
        c.create_resource("f", ResourceKind.FILE)
        c.perform_action("f", "open_read")
        assert c.check_potential_leak("f", True) is not None
        assert c.check_potential_leak("f", False) is None

    def test_check_use_after(self) -> None:
        """Test check_use_after behavior."""
        c = ResourceLifecycleChecker()
        c.create_resource("f", ResourceKind.FILE)
        c.perform_action("f", "open_read")
        c.perform_action("f", "close")
        assert c.check_use_after("f", "read") is not None

    def test_check_double_operation(self) -> None:
        """Test check_double_operation behavior."""
        c = ResourceLifecycleChecker()
        c.create_resource("f", ResourceKind.FILE)
        c.perform_action("f", "open_read")
        c.perform_action("f", "close")
        assert c.check_double_operation("f", "close") is not None

    def test_check_lock_ordering(self) -> None:
        """Test check_lock_ordering behavior."""
        c = ResourceLifecycleChecker()
        c.create_resource("L1", ResourceKind.LOCK)
        c.create_resource("L2", ResourceKind.LOCK)
        c.perform_action("L2", "acquire")
        c.perform_action("L1", "acquire")
        issue = c.check_lock_ordering(["L2", "L1"], ["L1", "L2"])
        assert issue is not None

    def test_check_potential_deadlock(self) -> None:
        """Test check_potential_deadlock behavior."""
        c = ResourceLifecycleChecker()
        issue = c.check_potential_deadlock({"L1": {"L2"}, "L2": {"L1"}})
        assert issue is not None

    def test_check_transaction_state(self) -> None:
        """Test check_transaction_state behavior."""
        c = ResourceLifecycleChecker()
        c.create_resource("t", ResourceKind.DATABASE_TRANSACTION)
        c.perform_action("t", "begin")
        assert c.check_transaction_state("t") is not None

    def test_suggest_context_manager(self) -> None:
        """Test suggest_context_manager behavior."""
        c = ResourceLifecycleChecker()
        c.create_resource("f", ResourceKind.FILE)
        c.perform_action("f", "open_read")
        c.perform_action("f", "read")
        c.perform_action("f", "close")
        assert c.suggest_context_manager("f") is not None

    @patch("pysymex.analysis.resources.lifecycle.z3.Solver.check", return_value=z3.unsat)
    def test_prove_resource_safety(self, mock_check) -> None:
        """Test prove_resource_safety behavior."""
        c = ResourceLifecycleChecker()
        c.create_resource("f", ResourceKind.FILE)
        safe, msg = c.prove_resource_safety("f")
        assert safe is True

    def test_get_all_issues(self) -> None:
        """Test get_all_issues behavior."""
        c = ResourceLifecycleChecker()
        c.create_resource("f", ResourceKind.FILE)
        c.perform_action("f", "open_read")
        assert len(c.get_all_issues()) > 0

    def test_get_resource_summary(self) -> None:
        """Test get_resource_summary behavior."""
        c = ResourceLifecycleChecker()
        c.create_resource("f", ResourceKind.FILE)
        s = c.get_resource_summary()
        assert "f" in s


class TestFileResourceChecker:
    """Test suite for pysymex.analysis.resources.lifecycle.FileResourceChecker."""

    def test_open_file(self) -> None:
        """Test open_file behavior."""
        c = FileResourceChecker()
        res, issue = c.open_file("f", "w")
        assert res.state == ResourceState.FILE_OPEN_WRITE

    def test_read_file(self) -> None:
        """Test read_file behavior."""
        c = FileResourceChecker()
        c.open_file("f", "r")
        assert c.read_file("f") is None

    def test_write_file(self) -> None:
        """Test write_file behavior."""
        c = FileResourceChecker()
        c.open_file("f", "w")
        assert c.write_file("f") is None

    def test_close_file(self) -> None:
        """Test close_file behavior."""
        c = FileResourceChecker()
        c.open_file("f", "r")
        assert c.close_file("f") is None


class TestLockResourceChecker:
    """Test suite for pysymex.analysis.resources.lifecycle.LockResourceChecker."""

    def test_create_lock(self) -> None:
        """Test create_lock behavior."""
        c = LockResourceChecker()
        res = c.create_lock("l")
        assert res.kind == ResourceKind.LOCK

    def test_acquire_lock(self) -> None:
        """Test acquire_lock behavior."""
        c = LockResourceChecker()
        c.create_lock("l")
        assert c.acquire_lock("l") is None

    def test_release_lock(self) -> None:
        """Test release_lock behavior."""
        c = LockResourceChecker()
        c.create_lock("l")
        c.acquire_lock("l")
        assert c.release_lock("l") is None

    def test_set_lock_order(self) -> None:
        """Test set_lock_order behavior."""
        c = LockResourceChecker()
        c.set_lock_order(["l1"])
        assert c._lock_order == ["l1"]

    def test_check_current_lock_order(self) -> None:
        """Test check_current_lock_order behavior."""
        c = LockResourceChecker()
        c.create_lock("l1")
        c.create_lock("l2")
        c.set_lock_order(["l1", "l2"])
        c.acquire_lock("l2")
        c.acquire_lock("l1")
        c._held_locks = {"l1", "l2"}
        assert c.check_lock_ordering(["l2", "l1"], ["l1", "l2"]) is not None
