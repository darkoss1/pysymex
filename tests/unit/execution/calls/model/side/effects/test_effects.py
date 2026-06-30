"""Tests for execution-owned model side-effect application."""

from __future__ import annotations

from typing import cast

from pysymex._internal.core.effects.events import WriteKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.calls.model.side.effects.application import (
    apply_model_side_effects,
)
from pysymex._internal.typing.protocols import StackValue


def test_generic_mutates_arg_side_effect_records_conservative_item_write() -> None:
    target: object = []
    target_value = cast("StackValue", target)
    state = VMState(local_vars={"items": target_value}, pc=9)

    application = apply_model_side_effects(
        state,
        [target_value],
        {"mutates_arg": 0},
        lambda _constraints: True,
    )

    assert application.issues == []
    assert application.state.write_events
    event = application.state.write_events[-1]
    assert event.kind == WriteKind.ITEM
    assert event.location == "items[*]"
    assert event.pc == 9
    assert event.precise is True
    assert event.source == "model.mutates_arg"
