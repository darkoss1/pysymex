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
from pysymex._internal.execution.opcodes.common.collections.subscript.delete import (
    handle_common_delete_subscr,
)
from pysymex._internal.execution.opcodes.common.collections.subscript.store import (
    handle_common_store_subscr,
)
from pysymex._internal.typing.protocols import StackValue
from tests.unit.execution.opcodes.common.collections_helpers import instr


def test_store_subscr_symbolic_dict_reports_unhashable_key_type_error() -> None:
    state = _state(stack=[3, SymbolicDict.empty("d"), [1]], pc=41)

    result = handle_common_store_subscr(instr("STORE_SUBSCR"), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "unhashable type: 'list'" in result.issues[0].message


def test_delete_subscr_symbolic_dict_reports_unhashable_key_type_error() -> None:
    state = _state(stack=[SymbolicDict.from_const({(1, 2): 3}), [1]], pc=42)

    result = handle_common_delete_subscr(instr("DELETE_SUBSCR"), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "unhashable type: 'list'" in result.issues[0].message


def test_store_subscr_symbolic_dict_preserves_tuple_key() -> None:
    mapping = SymbolicDict.from_const({})
    state = _state(stack=[3, mapping, (1, 2)], local_vars={"mapping": mapping}, pc=43)

    result = handle_common_store_subscr(instr("STORE_SUBSCR"), state, OpcodeDispatcher())

    updated = result.new_states[0].local_vars["mapping"]
    assert isinstance(updated, SymbolicDict)
    assert updated.concrete_items == {(1, 2): 3}


def test_delete_subscr_symbolic_dict_preserves_tuple_key() -> None:
    mapping = SymbolicDict.from_const({(1, 2): 3, "other": 4})
    state = _state(stack=[mapping, (1, 2)], local_vars={"mapping": mapping}, pc=44)

    result = handle_common_delete_subscr(instr("DELETE_SUBSCR"), state, OpcodeDispatcher())

    updated = result.new_states[0].local_vars["mapping"]
    assert isinstance(updated, SymbolicDict)
    assert updated.concrete_items == {"other": 4}


def test_store_subscr_symbolic_dict_degrades_symbolic_object_hashing() -> None:
    key, _constraint = SymbolicObject.symbolic("key_obj", 81)
    result = handle_common_store_subscr(
        instr("STORE_SUBSCR"),
        _state(stack=[3, SymbolicDict.empty("d"), key], pc=45),
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
    assert event.reason == "STORE_SUBSCR dict key requires symbolic or modeled object hashing"
    assert event.pc == 45
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_delete_subscr_symbolic_dict_degrades_symbolic_object_hashing() -> None:
    key, _constraint = SymbolicObject.symbolic("key_obj", 82)
    result = handle_common_delete_subscr(
        instr("DELETE_SUBSCR"),
        _state(stack=[SymbolicDict.empty("d"), key], pc=46),
        OpcodeDispatcher(),
    )

    assert not result.terminal
    assert result.degraded_passes == [
        CollectionFallbackEvents.UNSUPPORTED_HASHED_COLLECTION_PROTOCOL
    ]
    assert result.fallback_events[0].reason == (
        "DELETE_SUBSCR dict key requires symbolic or modeled object hashing"
    )


def _state(
    *,
    stack: list[object],
    local_vars: dict[str, object] | None = None,
    pc: int,
) -> VMState:
    return VMState(
        stack=cast("list[StackValue]", stack),
        local_vars=cast("dict[str, StackValue]", local_vars or {}),
        path_constraints=[z3.BoolVal(True)],
        pc=pc,
    )
