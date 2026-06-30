"""Tests for attribute access on havoc values."""

from __future__ import annotations

import dis

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.havoc import HavocValue
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.fallback.types import FallbackKind, RiskLevel, SoundnessTag
from pysymex._internal.execution.opcodes.common.functions.attribute.fallbacks import (
    UNMODELED_ATTRIBUTE_HAVOC,
)
from pysymex._internal.execution.opcodes.common.functions.attribute.load.handler import (
    handle_common_load_method,
)


def _instr(opname: str, argval: object = None) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval)


def test_havoc_attribute_read_records_precision_loss_event() -> None:
    obj, _constraint = HavocValue.havoc("source")
    state = VMState(stack=[obj], pc=23)

    result = handle_common_load_method(_instr("LOAD_ATTR", "dynamic"), state, OpcodeDispatcher())

    assert result.terminal is False
    assert result.degraded_passes == [UNMODELED_ATTRIBUTE_HAVOC]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.PRECISION_LOSS
    assert event.label == UNMODELED_ATTRIBUTE_HAVOC
    assert event.owner == "execution.opcodes.attribute"
    assert (
        event.reason
        == "havoc attribute 'dynamic' read from 'source' produced an unconstrained value"
    )
    assert event.pc == 23
    assert event.soundness is SoundnessTag.PRECISION_LOSS
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH

    next_state = result.new_states[0]
    assert next_state.pc == 24
    assert len(next_state.path_constraints) == 1
    assert isinstance(next_state.stack[-1], HavocValue)
