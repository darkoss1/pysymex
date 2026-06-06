"""Tests for resource lifecycle state machines."""

from __future__ import annotations

from pysymex.analysis.domains.resources.lifecycle.state_machine import ResourceStateMachine
from pysymex.analysis.domains.resources.lifecycle.tracked import TrackedResource
from pysymex.analysis.domains.resources.types import ResourceKind, ResourceState


class TestResourceStateMachine:
    """Test suite for pysymex.analysis.domains.resources.lifecycle.ResourceStateMachine."""

    def test_can_transition(self) -> None:
        sm = ResourceStateMachine(ResourceKind.FILE)
        assert sm.can_transition(ResourceState.UNINITIALIZED, "open_read") is True
        assert sm.can_transition(ResourceState.UNINITIALIZED, "read") is False

    def test_get_transition(self) -> None:
        sm = ResourceStateMachine(ResourceKind.FILE)
        transition = sm.get_transition(ResourceState.UNINITIALIZED, "open_read")
        assert transition is not None
        assert transition.to_state == ResourceState.FILE_OPEN_READ

    def test_is_final_state(self) -> None:
        sm = ResourceStateMachine(ResourceKind.FILE)
        assert sm.is_final_state(ResourceState.FILE_CLOSED) is True
        assert sm.is_final_state(ResourceState.FILE_OPEN_READ) is False

    def test_initial_state(self) -> None:
        sm = ResourceStateMachine(ResourceKind.FILE)
        assert sm.initial_state == ResourceState.UNINITIALIZED


class TestTrackedResource:
    """Test suite for pysymex.analysis.domains.resources.lifecycle.TrackedResource."""

    def test_record_action(self) -> None:
        sm = ResourceStateMachine(ResourceKind.FILE)
        tracked = TrackedResource("f", ResourceKind.FILE, ResourceState.UNINITIALIZED, sm)
        tracked.record_action("open_read", ResourceState.FILE_OPEN_READ, 10)
        assert tracked.state == ResourceState.FILE_OPEN_READ
        assert tracked.last_action_at == 10
        assert len(tracked.history) == 1
