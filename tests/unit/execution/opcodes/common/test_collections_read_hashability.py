from __future__ import annotations

from typing import cast

import z3

from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.fallback.types import FallbackKind, RiskLevel, SoundnessTag
from pysymex._internal.execution.opcodes.common.collections.fallbacks import (
    CollectionFallbackEvents,
)
from pysymex._internal.execution.opcodes.common.collections.read.handler import (
    handle_common_binary_subscr,
)
from pysymex._internal.typing.protocols import StackValue
from tests.unit.execution.opcodes.common.collections_helpers import instr


def test_binary_subscr_concrete_dict_reports_unhashable_key_type_error() -> None:
    result = handle_common_binary_subscr(
        instr("BINARY_SUBSCR"),
        _state(stack=[{}, [1]], pc=51),
        OpcodeDispatcher(),
    )

    assert result.terminal
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "unhashable type: 'list'" in result.issues[0].message


def test_binary_subscr_symbolic_dict_reports_unhashable_key_type_error() -> None:
    result = handle_common_binary_subscr(
        instr("BINARY_SUBSCR"),
        _state(stack=[SymbolicDict.from_const({}), [1]], pc=52),
        OpcodeDispatcher(),
    )

    assert result.terminal
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "unhashable type: 'list'" in result.issues[0].message


def test_binary_subscr_concrete_dict_preserves_tuple_key() -> None:
    result = handle_common_binary_subscr(
        instr("BINARY_SUBSCR"),
        _state(stack=[{(1, 2): 3}, (1, 2)], pc=53),
        OpcodeDispatcher(),
    )

    assert not result.terminal
    assert result.new_states[0].stack[-1] == 3


def test_binary_subscr_symbolic_dict_preserves_tuple_key() -> None:
    result = handle_common_binary_subscr(
        instr("BINARY_SUBSCR"),
        _state(stack=[SymbolicDict.from_const({(1, 2): 3}), (1, 2)], pc=54),
        OpcodeDispatcher(),
    )

    assert not result.terminal
    assert result.new_states[0].stack[-1] == 3


def test_binary_subscr_concrete_dict_reports_missing_tuple_key() -> None:
    result = handle_common_binary_subscr(
        instr("BINARY_SUBSCR"),
        _state(stack=[{}, (1, 2)], pc=55),
        OpcodeDispatcher(),
    )

    assert result.terminal
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.KEY_ERROR]


def test_binary_subscr_symbolic_dict_degrades_symbolic_object_hashing() -> None:
    key, _constraint = SymbolicObject.symbolic("key_obj", 91)
    result = handle_common_binary_subscr(
        instr("BINARY_SUBSCR"),
        _state(stack=[SymbolicDict.from_const({}), key], pc=56),
        OpcodeDispatcher(),
    )

    assert not result.terminal
    assert result.degraded_passes == [
        CollectionFallbackEvents.UNSUPPORTED_HASHED_COLLECTION_PROTOCOL
    ]
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == CollectionFallbackEvents.UNSUPPORTED_HASHED_COLLECTION_PROTOCOL
    assert event.owner == "execution.opcodes.collections"
    assert event.reason == "BINARY_SUBSCR dict key requires symbolic or modeled object hashing"
    assert event.pc == 56
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def _state(*, stack: list[object], pc: int) -> VMState:
    return VMState(
        stack=cast("list[StackValue]", stack),
        path_constraints=[z3.BoolVal(True)],
        pc=pc,
    )
