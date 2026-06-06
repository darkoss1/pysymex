"""Tests for execution-facing resource-limit policy helpers."""

from __future__ import annotations

from typing import cast

from pysymex.core.state.record import VMState
from pysymex.execution.fallback.types import FallbackKind
from pysymex.execution.resources import RESOURCE_LIMIT_PRUNE_REASON, check_step_depth_limit
from pysymex.execution.session.state import ExecutionSession
from pysymex.resources.models import LimitExceeded, ResourceType
from pysymex.resources.tracker import ResourceTracker


class _RejectDepthTracker:
    def check_depth_limit(self) -> None:
        raise LimitExceeded(ResourceType.DEPTH, 5, 4)


def test_check_step_depth_limit_allows_step_without_tracker() -> None:
    session = ExecutionSession()

    assert (
        check_step_depth_limit(
            session=session,
            resource_tracker=None,
            record_degraded_passes=session.record_degraded_passes,
            hook_owner=object(),
            hooks={},
            state=VMState(pc=3),
        )
        is True
    )
    assert session.paths_pruned == 0
    assert session.degraded_passes == []


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
        record_degraded_passes=session.record_degraded_passes,
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
