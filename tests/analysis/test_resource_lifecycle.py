"""Tests for resource_lifecycle module.

Tests the Z3-based resource lifecycle analysis including:
- Resource state machines
- File handle lifecycle
- Lock acquisition/release
- Leak detection
- State transition validation
"""

import pytest
import z3

from pysymex.analysis.resources.lifecycle import (
    ResourceIssue,
    ResourceIssueKind,
    ResourceKind,
    ResourceLifecycleChecker,
    ResourceState,
    ResourceStateMachine,
    StateTransition,
    TrackedResource,
)

# =============================================================================
# ResourceState Tests
# =============================================================================


class TestResourceState:
    """Tests for ResourceState enum."""

    def test_generic_states(self):
        """Test generic state values exist."""
        assert ResourceState.UNINITIALIZED
        assert ResourceState.INITIALIZED
        assert ResourceState.OPEN
        assert ResourceState.CLOSED

    def test_file_states(self):
        """Test file-specific states exist."""
        assert ResourceState.FILE_OPEN_READ
        assert ResourceState.FILE_OPEN_WRITE
        assert ResourceState.FILE_CLOSED
        assert ResourceState.FILE_EOF

    def test_lock_states(self):
        """Test lock-specific states exist."""
        assert ResourceState.LOCK_LOCKED
        assert ResourceState.LOCK_UNLOCKED
        assert ResourceState.LOCK_WAITING

    def test_transaction_states(self):
        """Test transaction states exist."""
        assert ResourceState.TRANSACTION_ACTIVE
        assert ResourceState.TRANSACTION_COMMITTED
        assert ResourceState.TRANSACTION_ROLLED_BACK

    def test_error_states(self):
        """Test error states exist."""
        assert ResourceState.ERROR
        assert ResourceState.LEAKED


# =============================================================================
# ResourceKind Tests
# =============================================================================


class TestResourceKind:
    """Tests for ResourceKind enum."""

    def test_common_kinds(self):
        """Test common resource kinds exist."""
        assert ResourceKind.FILE
        assert ResourceKind.LOCK
        assert ResourceKind.MEMORY
        assert ResourceKind.SOCKET

    def test_database_kinds(self):
        """Test database resource kinds exist."""
        assert ResourceKind.DATABASE_CONNECTION
        assert ResourceKind.DATABASE_CURSOR
        assert ResourceKind.DATABASE_TRANSACTION


# =============================================================================
# ResourceStateMachine Tests
# =============================================================================


class TestResourceStateMachine:
    """Tests for ResourceStateMachine class."""

    def test_file_state_machine(self):
        """Test file resource state machine."""
        sm = ResourceStateMachine(ResourceKind.FILE)

        assert sm.initial_state == ResourceState.UNINITIALIZED
        assert ResourceState.FILE_CLOSED in sm._final_states

    def test_lock_state_machine(self):
        """Test lock resource state machine."""
        sm = ResourceStateMachine(ResourceKind.LOCK)

        assert sm.initial_state == ResourceState.LOCK_UNLOCKED
        assert ResourceState.LOCK_UNLOCKED in sm._final_states

    def test_memory_state_machine(self):
        """Test memory resource state machine."""
        sm = ResourceStateMachine(ResourceKind.MEMORY)

        assert sm.initial_state == ResourceState.UNINITIALIZED
        assert ResourceState.FREED in sm._final_states

    def test_can_transition_valid(self):
        """Test valid transition check."""
        sm = ResourceStateMachine(ResourceKind.FILE)

        # Can open from uninitialized
        assert sm.can_transition(ResourceState.UNINITIALIZED, "open_read") is True

    def test_can_transition_invalid(self):
        """Test invalid transition check."""
        sm = ResourceStateMachine(ResourceKind.FILE)

        # Cannot read from uninitialized
        assert sm.can_transition(ResourceState.UNINITIALIZED, "read") is False

    def test_get_transition(self):
        """Test getting transition details."""
        sm = ResourceStateMachine(ResourceKind.FILE)

        trans = sm.get_transition(ResourceState.UNINITIALIZED, "open_read")

        assert trans is not None
        assert trans.from_state == ResourceState.UNINITIALIZED
        assert trans.to_state == ResourceState.FILE_OPEN_READ

    def test_get_transition_invalid(self):
        """Test getting invalid transition returns None."""
        sm = ResourceStateMachine(ResourceKind.FILE)

        trans = sm.get_transition(ResourceState.UNINITIALIZED, "invalid_action")

        assert trans is None

    def test_is_final_state(self):
        """Test final state check."""
        sm = ResourceStateMachine(ResourceKind.FILE)

        assert sm.is_final_state(ResourceState.FILE_CLOSED) is True
        assert sm.is_final_state(ResourceState.FILE_OPEN_READ) is False

    def test_db_transaction_state_machine(self):
        """Test database transaction state machine."""
        sm = ResourceStateMachine(ResourceKind.DATABASE_TRANSACTION)

        assert sm.initial_state == ResourceState.TRANSACTION_NONE
        assert sm.can_transition(ResourceState.TRANSACTION_NONE, "begin")
        assert sm.can_transition(ResourceState.TRANSACTION_ACTIVE, "commit")
        assert sm.can_transition(ResourceState.TRANSACTION_ACTIVE, "rollback")


# =============================================================================
# TrackedResource Tests
# =============================================================================


class TestTrackedResource:
    """Tests for TrackedResource class."""

    def test_resource_creation(self):
        """Test tracked resource creation."""
        sm = ResourceStateMachine(ResourceKind.FILE)
        resource = TrackedResource(
            name="myfile",
            kind=ResourceKind.FILE,
            state=sm.initial_state,
            state_machine=sm,
            created_at=10,
        )

        assert resource.name == "myfile"
        assert resource.kind == ResourceKind.FILE
        assert resource.state == ResourceState.UNINITIALIZED
        assert resource.created_at == 10

    def test_record_action(self):
        """Test recording actions on resource."""
        sm = ResourceStateMachine(ResourceKind.FILE)
        resource = TrackedResource(
            name="myfile",
            kind=ResourceKind.FILE,
            state=sm.initial_state,
            state_machine=sm,
        )

        resource.record_action("open_read", ResourceState.FILE_OPEN_READ, 20)

        assert resource.state == ResourceState.FILE_OPEN_READ
        assert resource.last_action_at == 20
        assert len(resource.history) == 1


# =============================================================================
# ResourceLifecycleChecker Tests
# =============================================================================


class TestResourceLifecycleChecker:
    """Tests for ResourceLifecycleChecker class."""

    @pytest.fixture
    def checker(self):
        return ResourceLifecycleChecker()

    def test_checker_creation(self, checker):
        """Test checker initialization."""
        assert checker.timeout_ms == 5000

    def test_create_resource(self, checker):
        """Test resource creation."""
        resource = checker.create_resource(
            name="myfile",
            kind=ResourceKind.FILE,
            line_number=10,
        )

        assert resource.name == "myfile"
        assert resource.kind == ResourceKind.FILE
        assert resource.state == ResourceState.UNINITIALIZED

    def test_get_resource(self, checker):
        """Test getting tracked resource."""
        checker.create_resource("myfile", ResourceKind.FILE)

        resource = checker.get_resource("myfile")
        assert resource is not None
        assert resource.name == "myfile"

    def test_get_resource_nonexistent(self, checker):
        """Test getting non-existent resource."""
        resource = checker.get_resource("nonexistent")
        assert resource is None

    def test_check_action_valid(self, checker):
        """Test valid action check."""
        checker.create_resource("myfile", ResourceKind.FILE)

        issue = checker.check_action("myfile", "open_read", line_number=10)

        assert issue is None
        resource = checker.get_resource("myfile")
        assert resource.state == ResourceState.FILE_OPEN_READ

    def test_check_action_invalid_state(self, checker):
        """Test invalid action for current state."""
        checker.create_resource("myfile", ResourceKind.FILE)

        # Try to read without opening first
        issue = checker.check_action("myfile", "read", line_number=10)

        assert issue is not None
        assert issue.kind == ResourceIssueKind.INVALID_STATE_TRANSITION

    def test_check_action_uninitialized(self, checker):
        """Test action on non-existent resource."""
        issue = checker.check_action("nonexistent", "read", line_number=10)

        assert issue is not None
        assert issue.kind == ResourceIssueKind.MISSING_INITIALIZATION

    def test_perform_action(self, checker):
        """Test performing action and getting new state."""
        checker.create_resource("myfile", ResourceKind.FILE)

        new_state, issue = checker.perform_action("myfile", "open_read", 10)

        assert issue is None
        assert new_state == ResourceState.FILE_OPEN_READ

    def test_perform_action_invalid(self, checker):
        """Test performing invalid action."""
        checker.create_resource("myfile", ResourceKind.FILE)

        new_state, issue = checker.perform_action("myfile", "read", 10)

        assert new_state is None
        assert issue is not None

    def test_file_lifecycle_complete(self, checker):
        """Test complete file lifecycle."""
        checker.create_resource("myfile", ResourceKind.FILE)

        # Open
        issue = checker.check_action("myfile", "open_read")
        assert issue is None

        # Read
        issue = checker.check_action("myfile", "read")
        assert issue is None

        # Close
        issue = checker.check_action("myfile", "close")
        assert issue is None

        # Check no leaks
        leaks = checker.check_leaks()
        assert len(leaks) == 0

    def test_check_leaks_with_leak(self, checker):
        """Test leak detection."""
        checker.create_resource("myfile", ResourceKind.FILE)
        checker.check_action("myfile", "open_read")
        # Never close

        leaks = checker.check_leaks()

        assert len(leaks) == 1
        assert leaks[0].kind == ResourceIssueKind.RESOURCE_LEAK
        assert leaks[0].resource_name == "myfile"

    def test_check_leaks_no_leak(self, checker):
        """Test no leak when properly closed."""
        checker.create_resource("myfile", ResourceKind.FILE)
        checker.check_action("myfile", "open_read")
        checker.check_action("myfile", "close")

        leaks = checker.check_leaks()

        assert len(leaks) == 0

    def test_check_potential_leak(self, checker):
        """Test potential leak detection."""
        checker.create_resource("myfile", ResourceKind.FILE)
        checker.check_action("myfile", "open_read")

        issue = checker.check_potential_leak("myfile", exception_possible=True)

        assert issue is not None
        assert issue.kind == ResourceIssueKind.POTENTIAL_LEAK
        assert issue.severity == "warning"

    def test_infeasible_path_suppresses_leak_reports(self, checker):
        """Unsatisfiable paths should not emit leak reports."""
        checker.create_resource("myfile", ResourceKind.FILE)
        checker.check_action("myfile", "open_read")

        impossible = [z3.BoolVal(False)]

        assert checker.check_leaks(impossible) == []
        assert checker.check_potential_leak("myfile", path_constraints=impossible) is None

    def test_infeasible_path_does_not_mutate_resource_state(self, checker):
        """Actions on impossible paths must not advance the tracked lifecycle."""
        checker.create_resource("myfile", ResourceKind.FILE)

        issue = checker.check_action("myfile", "open_read", path_constraints=[z3.BoolVal(False)])

        assert issue is None
        resource = checker.get_resource("myfile")
        assert resource is not None
        assert resource.state == ResourceState.UNINITIALIZED

    def test_lock_lifecycle(self, checker):
        """Test lock lifecycle."""
        checker.create_resource("mylock", ResourceKind.LOCK)

        # Acquire
        issue = checker.check_action("mylock", "acquire")
        assert issue is None

        resource = checker.get_resource("mylock")
        assert resource.state == ResourceState.LOCK_LOCKED

        # Release
        issue = checker.check_action("mylock", "release")
        assert issue is None

        # No leaks
        leaks = checker.check_leaks()
        assert len(leaks) == 0

    def test_double_close_detection(self, checker):
        """Test detecting double close."""
        checker.create_resource("myfile", ResourceKind.FILE)
        checker.check_action("myfile", "open_read")
        checker.check_action("myfile", "close")

        # Try to close again
        issue = checker.check_action("myfile", "close")

        assert issue is not None
        assert issue.kind == ResourceIssueKind.INVALID_STATE_TRANSITION

    def test_infeasible_path_suppresses_deadlock_report(self, checker):
        """Deadlock reports should not be emitted for impossible paths."""
        deps = {"lock_a": {"lock_b"}, "lock_b": {"lock_a"}}

        issue = checker.check_potential_deadlock(deps, path_constraints=[z3.BoolVal(False)])

        assert issue is None

    def test_checker_reset(self, checker):
        """Test checker reset."""
        checker.create_resource("myfile", ResourceKind.FILE)
        checker.reset()

        # Resource should be gone
        assert checker.get_resource("myfile") is None


# =============================================================================
# ResourceIssue Tests
# =============================================================================


class TestResourceIssue:
    """Tests for ResourceIssue class."""

    def test_issue_creation(self):
        """Test issue creation."""
        issue = ResourceIssue(
            kind=ResourceIssueKind.RESOURCE_LEAK,
            message="File not closed",
            resource_kind=ResourceKind.FILE,
            resource_name="myfile",
            current_state=ResourceState.FILE_OPEN_READ,
            line_number=42,
        )

        assert issue.kind == ResourceIssueKind.RESOURCE_LEAK
        assert issue.resource_name == "myfile"
        assert issue.line_number == 42

    def test_issue_format(self):
        """Test issue formatting."""
        issue = ResourceIssue(
            kind=ResourceIssueKind.RESOURCE_LEAK,
            message="File not closed",
            resource_name="myfile",
            current_state=ResourceState.FILE_OPEN_READ,
            line_number=42,
        )

        formatted = issue.format()
        assert "RESOURCE_LEAK" in formatted
        assert "42" in formatted
        assert "myfile" in formatted
        assert "FILE_OPEN_READ" in formatted


# =============================================================================
# ResourceIssueKind Tests
# =============================================================================


class TestResourceIssueKind:
    """Tests for ResourceIssueKind enum."""

    def test_leak_issues(self):
        """Test leak-related issue kinds exist."""
        assert ResourceIssueKind.RESOURCE_LEAK
        assert ResourceIssueKind.POTENTIAL_LEAK

    def test_use_after_issues(self):
        """Test use-after issue kinds exist."""
        assert ResourceIssueKind.USE_AFTER_CLOSE
        assert ResourceIssueKind.USE_AFTER_FREE
        assert ResourceIssueKind.USE_AFTER_RELEASE

    def test_double_issues(self):
        """Test double-action issue kinds exist."""
        assert ResourceIssueKind.DOUBLE_CLOSE
        assert ResourceIssueKind.DOUBLE_FREE
        assert ResourceIssueKind.DOUBLE_RELEASE

    def test_lock_issues(self):
        """Test lock-related issue kinds exist."""
        assert ResourceIssueKind.DEADLOCK_POTENTIAL
        assert ResourceIssueKind.LOCK_ORDER_VIOLATION

    def test_context_manager_issues(self):
        """Test context manager issue kinds exist."""
        assert ResourceIssueKind.MISSING_CONTEXT_MANAGER
        assert ResourceIssueKind.CONTEXT_MANAGER_MISUSE


# =============================================================================
# StateTransition Tests
# =============================================================================


class TestStateTransition:
    """Tests for StateTransition class."""

    def test_transition_creation(self):
        """Test state transition creation."""
        trans = StateTransition(
            from_state=ResourceState.UNINITIALIZED,
            to_state=ResourceState.FILE_OPEN_READ,
            action="open_read",
        )

        assert trans.from_state == ResourceState.UNINITIALIZED
        assert trans.to_state == ResourceState.FILE_OPEN_READ
        assert trans.action == "open_read"

    def test_transition_with_conditions(self):
        """Test transition with pre/postconditions."""
        trans = StateTransition(
            from_state=ResourceState.UNINITIALIZED,
            to_state=ResourceState.FILE_OPEN_READ,
            action="open_read",
            preconditions=["file_exists"],
            postconditions=["handle_valid"],
        )

        assert len(trans.preconditions) == 1
        assert len(trans.postconditions) == 1
