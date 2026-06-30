"""Tests for execution-facing resource-limit policy helpers."""

from __future__ import annotations

from typing import cast

from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.fallback.types import FallbackKind
from pysymex._internal.execution.resources.events import (
    RESOURCE_LIMIT_PRUNE_REASON,
    record_resource_limit_degradation,
)
from pysymex._internal.execution.resources.step import check_step_depth_limit
from pysymex._internal.execution.session.state.core import ExecutionSession
from pysymex._internal.limits.models import LimitExceeded, ResourceLimits, ResourceType
from pysymex._internal.limits.tracker import ResourceTracker


class _RejectDepthTracker:
    def __init__(self) -> None:
        self.limits = ResourceLimits(max_depth=4)

    def check_depth_limit(self) -> None:
        raise LimitExceeded(ResourceType.DEPTH, 5, 4)


def test_record_resource_limit_degradation_records_fallback_without_prune() -> None:
    session = ExecutionSession()
    state = VMState(pc=11)
    exc = LimitExceeded(ResourceType.PATHS, 5, 4)

    record_resource_limit_degradation(
        exc=exc,
        session=session,
        state=state,
    )

    event = session.fallback_events[-1]
    assert session.paths_pruned == 0
    assert session.degraded_passes == ["resource_limit_paths"]
    assert event.kind is FallbackKind.RESOURCE_LIMIT
    assert event.label == "resource_limit_paths"
    assert event.pc == 11


def test_check_step_depth_limit_allows_step_without_tracker() -> None:
    session = ExecutionSession()

    assert (
        check_step_depth_limit(
            session=session,
            resource_tracker=None,
            hook_owner=object(),
            hooks={},
            state=VMState(pc=3),
        )
        is True
    )
    assert session.paths_pruned == 0
    assert session.degraded_passes == []


def test_check_step_depth_limit_allows_automatic_depth() -> None:
    session = ExecutionSession()
    tracker = ResourceTracker(ResourceLimits(max_depth=None))

    assert (
        check_step_depth_limit(
            session=session,
            resource_tracker=tracker,
            hook_owner=object(),
            hooks={},
            state=VMState(pc=3, depth=10_000),
        )
        is True
    )
    assert session.paths_pruned == 0


def test_check_step_depth_limit_records_depth_prune_and_hook() -> None:
    session = ExecutionSession()
    state = VMState(pc=7)
    owner = object()
    seen: list[tuple[object, VMState, str]] = []

    def hook(hook_owner: object, pruned_state: VMState, reason: str) -> None:
        seen.append((hook_owner, pruned_state, reason))

    result = check_step_depth_limit(
        session=session,
        resource_tracker=cast("ResourceTracker", _RejectDepthTracker()),
        hook_owner=owner,
        hooks={"on_prune": [hook]},
        state=state,
    )

    event = session.fallback_events[-1]
    assert result is False
    assert session.paths_pruned == 1
    assert session.degraded_passes == ["resource_limit_depth"]
    assert event.kind is FallbackKind.RESOURCE_LIMIT
    assert event.label == "resource_limit_depth"
    assert event.owner == "execution.resources"
    assert event.pc == 7
    assert seen == [(owner, state, RESOURCE_LIMIT_PRUNE_REASON)]


def test_check_step_depth_limit_uses_vm_state_depth() -> None:
    session = ExecutionSession()
    tracker = ResourceTracker(ResourceLimits(max_depth=3))
    state = VMState(pc=9, depth=3)

    result = check_step_depth_limit(
        session=session,
        resource_tracker=tracker,
        hook_owner=object(),
        hooks={},
        state=state,
    )

    event = session.fallback_events[-1]
    assert result is False
    assert session.paths_pruned == 1
    assert session.degraded_passes == ["resource_limit_depth"]
    assert event.kind is FallbackKind.RESOURCE_LIMIT
    assert event.label == "resource_limit_depth"
    assert event.pc == 9
