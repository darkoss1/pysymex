from __future__ import annotations

from typing import cast

import pytest
import z3

from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.state.types import VMStateError
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.fallback.types import FallbackKind, RiskLevel, SoundnessTag
from pysymex._internal.execution.opcodes.common.collections.build import handle_common_build_map
from pysymex._internal.execution.opcodes.common.collections.fallbacks import (
    CollectionFallbackEvents,
)
from pysymex._internal.execution.opcodes.common.collections.mutation.dicts import (
    handle_common_collection_update,
)
from pysymex._internal.execution.opcodes.common.collections.mutation.items import (
    handle_common_list_append,
    handle_common_list_extend,
)
from pysymex._internal.execution.opcodes.common.collections.mutation.map_add import (
    handle_common_map_add,
)
from pysymex._internal.execution.opcodes.common.collections.mutation.sets import (
    handle_common_set_add,
)
from pysymex._internal.typing.protocols import StackValue
from tests.unit.execution.opcodes.common.collections_helpers import instr


def test_handle_common_list_append_rejects_missing_container() -> None:
    state = VMState(stack=[9], pc=13)
    with pytest.raises(VMStateError, match="LIST_APPEND"):
        handle_common_list_append(instr("LIST_APPEND", 1), state, OpcodeDispatcher())


def test_handle_common_list_append_accepts_non_integer_symbolic_values() -> None:
    container = SymbolicList.empty("items")
    value = SymbolicString.from_const("x")
    state = VMState(stack=[container, value], pc=25)
    result = handle_common_list_append(instr("LIST_APPEND", 1), state, OpcodeDispatcher())
    updated = result.new_states[0].stack[0]
    assert isinstance(updated, SymbolicList)
    assert z3.is_true(simplify_expr(updated.z3_len == z3.IntVal(1)))


def test_handle_common_list_append_replaces_float_sorted_symbolic_payloads() -> None:
    container = SymbolicList.empty("items")
    value = SymbolicValue.from_const(1)
    object.__setattr__(value, "z3_int", z3.RealVal("1.25"))
    state = VMState(stack=[container, value], pc=26)

    result = handle_common_list_append(instr("LIST_APPEND", 1), state, OpcodeDispatcher())

    updated = result.new_states[0].stack[0]
    assert isinstance(updated, SymbolicList)
    stored = simplify_expr(z3.Select(updated.z3_array, z3.IntVal(0)))
    assert z3.is_int(stored)


def test_handle_common_list_append_preserves_nested_list_handle() -> None:
    container = SymbolicList.from_const([])
    nested = SymbolicList.from_const([1])
    handle = SymbolicObject("list_41", 41, z3.IntVal(41), {41})
    state = VMState(stack=[container, handle], memory={41: nested}, pc=27)

    result = handle_common_list_append(instr("LIST_APPEND", 1), state, OpcodeDispatcher())

    updated = result.new_states[0].stack[0]
    assert isinstance(updated, SymbolicList)
    assert updated.concrete_items == [handle]
    assert result.new_states[0].memory[41] is nested
    stored = simplify_expr(z3.Select(updated.z3_array, z3.IntVal(0)))
    assert z3.is_true(simplify_expr(stored == handle.z3_addr))


def test_handle_common_list_append_materializes_raw_nested_list() -> None:
    container = SymbolicList.from_const([])
    nested = SymbolicList.from_const([1])
    state = VMState(stack=[container, nested], pc=28)

    result = handle_common_list_append(instr("LIST_APPEND", 1), state, OpcodeDispatcher())

    updated = result.new_states[0].stack[0]
    assert isinstance(updated, SymbolicList)
    concrete_items = updated.concrete_items
    assert concrete_items is not None
    assert len(concrete_items) == 1
    handle = concrete_items[0]
    assert isinstance(handle, SymbolicObject)
    assert result.new_states[0].memory[handle.address] is nested
    stored = simplify_expr(z3.Select(updated.z3_array, z3.IntVal(0)))
    assert z3.is_true(simplify_expr(stored == handle.z3_addr))


def test_handle_common_list_extend_reports_unsupported_iterable_operand() -> None:
    container = SymbolicList.empty("items")
    unknown_iterable, constraint = SymbolicValue.symbolic("unknown_iterable")
    state = VMState(stack=[container, unknown_iterable], path_constraints=[constraint], pc=57)

    result = handle_common_list_extend(instr("LIST_EXTEND", 1), state, OpcodeDispatcher())

    assert result.new_states[0].pc == 58
    assert result.degraded_passes == [
        CollectionFallbackEvents.UNSUPPORTED_COLLECTION_MUTATION_PROTOCOL
    ]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == CollectionFallbackEvents.UNSUPPORTED_COLLECTION_MUTATION_PROTOCOL
    assert event.owner == "execution.opcodes.collections"
    assert event.reason == "LIST_EXTEND source iterable is not retained as a concrete sequence"
    assert event.pc == 57
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_handle_common_set_add_rejects_missing_container() -> None:
    state = VMState(stack=[9], pc=58)
    with pytest.raises(VMStateError, match="SET_ADD"):
        handle_common_set_add(instr("SET_ADD", 1), state, OpcodeDispatcher())


def test_handle_common_set_add_updates_concrete_backed_symbolic_set() -> None:
    target = SymbolicValue.from_const(set[object]())
    target.set_runtime_type("set")
    state = VMState(stack=[target, 7], pc=59)

    result = handle_common_set_add(instr("SET_ADD", 1), state, OpcodeDispatcher())

    updated = result.new_states[0].stack[0]
    assert isinstance(updated, SymbolicValue)
    assert updated.value == {7}
    assert updated.type_tag == "set"
    assert z3.is_true(simplify_expr(updated.z3_int == z3.IntVal(1)))
    assert result.degraded_passes == []
    assert result.fallback_events == []


def test_handle_common_set_add_reports_symbolic_hashing_limitation() -> None:
    target = SymbolicValue.from_const(set[object]())
    target.set_runtime_type("set")
    value, constraint = SymbolicValue.symbolic("set_item")
    state = VMState(stack=[target, value], path_constraints=[constraint], pc=60)

    result = handle_common_set_add(instr("SET_ADD", 1), state, OpcodeDispatcher())

    assert result.new_states[0].pc == 61
    assert result.degraded_passes == [
        CollectionFallbackEvents.UNSUPPORTED_HASHED_COLLECTION_PROTOCOL
    ]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == CollectionFallbackEvents.UNSUPPORTED_HASHED_COLLECTION_PROTOCOL
    assert event.reason == "SET_ADD element requires symbolic or modeled object hashing"
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_handle_common_set_add_reports_unhashable_concrete_element() -> None:
    target = SymbolicValue.from_const(set[object]())
    target.set_runtime_type("set")
    state = VMState(stack=cast("list[StackValue]", [target, [1]]), pc=61)

    result = handle_common_set_add(instr("SET_ADD", 1), state, OpcodeDispatcher())

    assert result.terminal
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "unhashable type: 'list'" in result.issues[0].message


def test_handle_common_set_update_updates_concrete_backed_symbolic_set() -> None:
    target = SymbolicValue.from_const(set[object]())
    target.set_runtime_type("set")
    state = VMState(stack=cast("list[StackValue]", [target, [2, 3]]), pc=62)

    result = handle_common_collection_update(instr("SET_UPDATE", 1), state, OpcodeDispatcher())

    updated = result.new_states[0].stack[0]
    assert isinstance(updated, SymbolicValue)
    assert updated.value == {2, 3}
    assert updated.type_tag == "set"
    assert z3.is_true(simplify_expr(updated.z3_int == z3.IntVal(2)))
    assert result.degraded_passes == []
    assert result.fallback_events == []


def test_handle_common_set_update_reports_unsupported_iterable_source() -> None:
    target = SymbolicValue.from_const(set[object]())
    target.set_runtime_type("set")
    value, constraint = SymbolicValue.symbolic("set_update_source")
    state = VMState(stack=[target, value], path_constraints=[constraint], pc=63)

    result = handle_common_collection_update(instr("SET_UPDATE", 1), state, OpcodeDispatcher())

    assert result.new_states[0].pc == 64
    assert result.degraded_passes == [
        CollectionFallbackEvents.UNSUPPORTED_COLLECTION_MUTATION_PROTOCOL
    ]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == CollectionFallbackEvents.UNSUPPORTED_COLLECTION_MUTATION_PROTOCOL
    assert (
        event.reason == "SET_UPDATE source iterable is not retained as a concrete sequence or set"
    )
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_handle_common_set_update_reports_unhashable_concrete_element() -> None:
    target = SymbolicValue.from_const(set[object]())
    target.set_runtime_type("set")
    state = VMState(stack=cast("list[StackValue]", [target, [[1]]]), pc=64)

    result = handle_common_collection_update(instr("SET_UPDATE", 1), state, OpcodeDispatcher())

    assert result.terminal
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "unhashable type: 'list'" in result.issues[0].message


def test_handle_common_map_add_rejects_missing_container() -> None:
    state = VMState(stack=["k", 1], pc=14)
    with pytest.raises(VMStateError, match="MAP_ADD"):
        handle_common_map_add(instr("MAP_ADD", 1), state, OpcodeDispatcher())


def test_handle_common_map_add_preserves_concrete_integer_key() -> None:
    build_result = handle_common_build_map(
        instr("BUILD_MAP", 0, arg=0),
        VMState(pc=27),
        OpcodeDispatcher(),
    )
    state = build_result.new_states[0].push(1).push(2)

    result = handle_common_map_add(instr("MAP_ADD", 1), state, OpcodeDispatcher())

    updated = result.new_states[0].stack[0]
    assert isinstance(updated, SymbolicDict)
    assert updated.concrete_value_for_key(1) == (True, 2)
    assert updated.concrete_value_for_key("1") == (False, None)


def test_handle_common_map_add_preserves_symbolic_none_key() -> None:
    build_result = handle_common_build_map(
        instr("BUILD_MAP", 0, arg=0),
        VMState(pc=65),
        OpcodeDispatcher(),
    )
    state = build_result.new_states[0].push(SymbolicNoneType()).push(2)

    result = handle_common_map_add(instr("MAP_ADD", 1), state, OpcodeDispatcher())

    updated = result.new_states[0].stack[0]
    assert isinstance(updated, SymbolicDict)
    assert updated.concrete_value_for_key(None) == (True, 2)


def test_handle_common_map_add_reports_unhashable_key_type_error() -> None:
    build_result = handle_common_build_map(
        instr("BUILD_MAP", 0, arg=0),
        VMState(pc=66),
        OpcodeDispatcher(),
    )
    state = build_result.new_states[0].push([1]).push(2)

    result = handle_common_map_add(instr("MAP_ADD", 1), state, OpcodeDispatcher())

    assert result.terminal
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "unhashable type: 'list'" in result.issues[0].message


def test_handle_common_map_add_reports_symbolic_object_hashing_limitation() -> None:
    build_result = handle_common_build_map(
        instr("BUILD_MAP", 0, arg=0),
        VMState(pc=67),
        OpcodeDispatcher(),
    )
    key = SymbolicObject("key", 500, z3.IntVal(500), {500})
    state = build_result.new_states[0].push(key).push(2)
    pc_before = state.pc

    result = handle_common_map_add(instr("MAP_ADD", 1), state, OpcodeDispatcher())

    assert result.new_states[0].pc == pc_before + 1
    assert result.degraded_passes == [
        CollectionFallbackEvents.UNSUPPORTED_HASHED_COLLECTION_PROTOCOL
    ]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == CollectionFallbackEvents.UNSUPPORTED_HASHED_COLLECTION_PROTOCOL
    assert event.reason == "MAP_ADD key requires symbolic or modeled object hashing"
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH
