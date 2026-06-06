from __future__ import annotations

import pytest
import z3

from pysymex.core.state.record import VMState
from pysymex.core.state.types import VMStateError
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.common.collections.build import handle_common_build_map
from pysymex.execution.opcodes.common.collections.mutation import (
    handle_common_list_append,
    handle_common_map_add,
)
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
    assert z3.is_true(z3.simplify(updated.z3_len == z3.IntVal(1)))


def test_handle_common_list_append_replaces_float_sorted_symbolic_payloads() -> None:
    container = SymbolicList.empty("items")
    value = SymbolicValue.from_const(1)
    object.__setattr__(value, "z3_int", z3.RealVal("1.25"))
    state = VMState(stack=[container, value], pc=26)

    result = handle_common_list_append(instr("LIST_APPEND", 1), state, OpcodeDispatcher())

    updated = result.new_states[0].stack[0]
    assert isinstance(updated, SymbolicList)
    stored = z3.simplify(z3.Select(updated.z3_array, z3.IntVal(0)))
    assert z3.is_int(stored)


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
