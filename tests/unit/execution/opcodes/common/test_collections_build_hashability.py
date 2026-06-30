from __future__ import annotations

import dataclasses

from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.collections.build import (
    handle_common_build_const_key_map,
    handle_common_build_map,
    handle_common_build_set,
)
from tests.unit.execution.opcodes.common.collections_helpers import instr


def _result_dict(result: OpcodeResult) -> SymbolicDict:
    value = result.new_states[0].stack[-1]
    assert isinstance(value, SymbolicDict)
    return value


def _tuple_carrier(*items: object) -> SymbolicList:
    return dataclasses.replace(SymbolicList.from_const(list(items)), _type="tuple")


def test_handle_common_build_set_reports_unhashable_element_type_error() -> None:
    result = handle_common_build_set(
        instr("BUILD_SET", 1),
        VMState(stack=[[1]], pc=31),
        OpcodeDispatcher(),
    )

    assert result.terminal
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "unhashable type: 'list'" in result.issues[0].message


def test_handle_common_build_map_reports_unhashable_key_type_error() -> None:
    result = handle_common_build_map(
        instr("BUILD_MAP", 1),
        VMState(stack=[[1], 3], pc=32),
        OpcodeDispatcher(),
    )

    assert result.terminal
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "unhashable type: 'list'" in result.issues[0].message


def test_handle_common_build_const_key_map_reports_unhashable_key_type_error() -> None:
    result = handle_common_build_const_key_map(
        instr("BUILD_CONST_KEY_MAP", 1),
        VMState(stack=[3, ([1],)], pc=33),
        OpcodeDispatcher(),
    )

    assert result.terminal
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "unhashable type: 'list'" in result.issues[0].message


def test_handle_common_build_map_preserves_tuple_key() -> None:
    result = handle_common_build_map(
        instr("BUILD_MAP", 1),
        VMState(stack=[(1, 2), 3], pc=34),
        OpcodeDispatcher(),
    )

    assert not result.terminal
    assert _result_dict(result).concrete_items == {(1, 2): 3}


def test_handle_common_build_map_preserves_symbolic_tuple_key() -> None:
    key = _tuple_carrier("nested", SymbolicValue.from_const(3))

    result = handle_common_build_map(
        instr("BUILD_MAP", 1),
        VMState(stack=[key, 3], pc=35),
        OpcodeDispatcher(),
    )

    assert not result.terminal
    concrete_items = _result_dict(result).concrete_items
    assert concrete_items is not None
    assert list(concrete_items) == [("nested", 3)]
    assert concrete_items[("nested", 3)] == 3


def test_handle_common_build_map_reports_nested_unhashable_symbolic_tuple_key() -> None:
    key = _tuple_carrier([1])

    result = handle_common_build_map(
        instr("BUILD_MAP", 1),
        VMState(stack=[key, 3], pc=36),
        OpcodeDispatcher(),
    )

    assert result.terminal
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "unhashable type: 'list'" in result.issues[0].message


def test_handle_common_build_const_key_map_preserves_tuple_key() -> None:
    result = handle_common_build_const_key_map(
        instr("BUILD_CONST_KEY_MAP", 1),
        VMState(stack=[3, ((1, 2),)], pc=37),
        OpcodeDispatcher(),
    )

    assert not result.terminal
    assert _result_dict(result).concrete_items == {(1, 2): 3}
