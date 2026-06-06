"""Tests for scheduling-owned state-merger handoff policy."""

from __future__ import annotations

from typing import cast

from pysymex.core.state.record import VMState
from pysymex.execution.scheduling.merging import offer_state_to_merger
from pysymex.execution.session.state import ExecutionSession
from pysymex.execution.strategies.merger.state import StateMerger


class _MergerDouble:
    def __init__(self, *, should_merge: bool, merged: VMState | None) -> None:
        self.should_merge_result = should_merge
        self.merged = merged
        self.offered: list[VMState] = []

    def should_merge(self, state: VMState) -> bool:
        self.offered.append(state)
        return self.should_merge_result

    def add_state_for_merge(self, state: VMState) -> VMState | None:
        self.offered.append(state)
        return self.merged


def test_offer_state_to_merger_returns_state_when_merger_is_disabled() -> None:
    session = ExecutionSession()
    state = VMState(pc=3)

    assert offer_state_to_merger(session=session, state_merger=None, state=state) is state
    assert session.paths_pruned == 0


def test_offer_state_to_merger_returns_state_when_not_mergeable() -> None:
    session = ExecutionSession()
    state = VMState(pc=3)
    merger = _MergerDouble(should_merge=False, merged=None)

    result = offer_state_to_merger(
        session=session,
        state_merger=cast("StateMerger", merger),
        state=state,
    )

    assert result is state
    assert session.paths_pruned == 0
    assert merger.offered == [state]


def test_offer_state_to_merger_prunes_absorbed_state() -> None:
    session = ExecutionSession()
    state = VMState(pc=3)
    merger = _MergerDouble(should_merge=True, merged=None)

    result = offer_state_to_merger(
        session=session,
        state_merger=cast("StateMerger", merger),
        state=state,
    )

    assert result is None
    assert session.paths_pruned == 1
    assert merger.offered == [state, state]


def test_offer_state_to_merger_returns_merged_state() -> None:
    session = ExecutionSession()
    state = VMState(pc=3)
    merged = VMState(pc=9)
    merger = _MergerDouble(should_merge=True, merged=merged)

    result = offer_state_to_merger(
        session=session,
        state_merger=cast("StateMerger", merger),
        state=state,
    )

    assert result is merged
    assert session.paths_pruned == 0
    assert merger.offered == [state, state]
