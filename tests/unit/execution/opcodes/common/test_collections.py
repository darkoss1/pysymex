from __future__ import annotations

import dis
from typing import cast

import pytest
import z3

from pysymex._typing import StackValue
from pysymex.analysis.detectors import IssueKind
from pysymex.core.state import VMState, VMStateError
from pysymex.core.types import SymbolicDict, SymbolicList, SymbolicObject, SymbolicString
from pysymex.core.types.scalars import SymbolicValue
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.common.collections import (
    handle_common_binary_subscr,
    handle_common_build_const_key_map,
    handle_common_build_list,
    handle_common_build_set,
    handle_common_delete_subscr,
    handle_common_dict_merge_update,
    handle_common_list_append,
    handle_common_map_add,
    handle_common_unpack_ex,
    handle_common_unpack_sequence,
)


def _instr(opname: str, argval: object = None, arg: int = 0, offset: int = 0) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval, arg=arg, offset=offset)


def test_handle_common_build_list_rejects_missing_elements() -> None:
    state = VMState(stack=[1], pc=10)

    with pytest.raises(VMStateError, match="BUILD_LIST"):
        handle_common_build_list(_instr("BUILD_LIST", 2), state, OpcodeDispatcher())


def test_handle_common_build_const_key_map_rejects_missing_keys_tuple() -> None:
    state = VMState(stack=[1], pc=11)

    with pytest.raises(VMStateError, match="BUILD_CONST_KEY_MAP"):
        handle_common_build_const_key_map(
            _instr("BUILD_CONST_KEY_MAP", 1),
            state,
            OpcodeDispatcher(),
        )


def test_handle_common_build_const_key_map_preserves_unknown_key_count() -> None:
    keys, constraint = SymbolicValue.symbolic("keys")
    state = VMState(stack=[10, 20, keys], pc=21).add_constraint(constraint)

    result = handle_common_build_const_key_map(
        _instr("BUILD_CONST_KEY_MAP", 2),
        state,
        OpcodeDispatcher(),
    )

    next_state = result.new_states[0]
    mapping = next_state.stack[-1]
    assert isinstance(mapping, SymbolicDict)
    assert z3.is_true(z3.simplify(mapping.z3_len == 2))


def test_handle_common_binary_subscr_rejects_missing_index() -> None:
    state = VMState(stack=[[1, 2, 3]], pc=12)

    with pytest.raises(VMStateError, match="BINARY_SUBSCR"):
        handle_common_binary_subscr(_instr("BINARY_SUBSCR"), state, OpcodeDispatcher())


def test_handle_common_binary_subscr_preserves_concrete_list_lookup() -> None:
    state = VMState(stack=[[11, 22, 33], 1], pc=17)

    result = handle_common_binary_subscr(_instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    assert not result.terminal
    assert len(result.new_states) == 1
    assert result.new_states[0].stack[-1] == 22


def test_handle_common_binary_subscr_terminates_uncaught_concrete_index_error() -> None:
    state = VMState(stack=[[11], 4], pc=18)

    result = handle_common_binary_subscr(_instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []


def test_handle_common_build_set_preserves_concrete_set_semantics() -> None:
    state = VMState(stack=[1, 1, 2], pc=19)

    result = handle_common_build_set(_instr("BUILD_SET", 3), state, OpcodeDispatcher())

    assert not result.terminal
    assert len(result.new_states) == 1
    set_value = result.new_states[0].stack[-1]
    assert getattr(set_value, "value") == {1, 2}


def test_handle_common_build_set_terminates_uncaught_unhashable_element() -> None:
    state = VMState(stack=[[1]], pc=20)

    result = handle_common_build_set(_instr("BUILD_SET", 1), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []


def test_handle_common_build_list_stores_nested_symbolic_container_address() -> None:
    nested = SymbolicList.empty("nested")
    state = VMState(stack=[nested], pc=22)

    result = handle_common_build_list(_instr("BUILD_LIST", 1), state, OpcodeDispatcher())

    next_state = result.new_states[0]
    handle = next_state.stack[-1]
    assert isinstance(handle, SymbolicObject)
    outer = next_state.memory[handle.address]
    assert isinstance(outer, SymbolicList)
    nested_addresses = [address for address, value in next_state.memory.items() if value is nested]
    assert len(nested_addresses) == 1
    stored_address = z3.simplify(z3.Select(outer.z3_array, z3.IntVal(0)))
    assert z3.is_true(z3.simplify(stored_address == z3.IntVal(nested_addresses[0])))


def test_handle_common_binary_subscr_recovers_nested_symbolic_container() -> None:
    nested = SymbolicList.empty("nested")
    build_state = VMState(stack=[nested], pc=23)
    build_result = handle_common_build_list(
        _instr("BUILD_LIST", 1), build_state, OpcodeDispatcher()
    )
    built_state = build_result.new_states[0]
    handle = built_state.stack[-1]
    built_state = built_state.push(0)

    result = handle_common_binary_subscr(_instr("BINARY_SUBSCR"), built_state, OpcodeDispatcher())

    assert not result.terminal
    assert result.new_states[0].stack[-1] is nested
    assert isinstance(handle, SymbolicObject)


def test_handle_common_build_list_preserves_repeated_nested_alias_address() -> None:
    nested = SymbolicList.empty("nested")
    state = VMState(stack=[nested, nested], pc=24)

    result = handle_common_build_list(_instr("BUILD_LIST", 2), state, OpcodeDispatcher())

    next_state = result.new_states[0]
    handle = next_state.stack[-1]
    assert isinstance(handle, SymbolicObject)
    outer = next_state.memory[handle.address]
    assert isinstance(outer, SymbolicList)
    nested_addresses = [address for address, value in next_state.memory.items() if value is nested]
    assert len(nested_addresses) == 1
    first_address = z3.simplify(z3.Select(outer.z3_array, z3.IntVal(0)))
    second_address = z3.simplify(z3.Select(outer.z3_array, z3.IntVal(1)))
    assert z3.is_true(z3.simplify(first_address == z3.IntVal(nested_addresses[0])))
    assert z3.is_true(z3.simplify(second_address == z3.IntVal(nested_addresses[0])))


def test_handle_common_list_append_rejects_missing_container() -> None:
    state = VMState(stack=[9], pc=13)

    with pytest.raises(VMStateError, match="LIST_APPEND"):
        handle_common_list_append(_instr("LIST_APPEND", 1), state, OpcodeDispatcher())


def test_handle_common_list_append_accepts_non_integer_symbolic_values() -> None:
    container = SymbolicList.empty("items")
    value = SymbolicString.from_const("x")
    state = VMState(stack=[container, value], pc=25)

    result = handle_common_list_append(_instr("LIST_APPEND", 1), state, OpcodeDispatcher())

    next_state = result.new_states[0]
    updated = next_state.stack[0]
    assert isinstance(updated, SymbolicList)
    assert z3.is_true(z3.simplify(updated.z3_len == z3.IntVal(1)))


def test_handle_common_list_append_replaces_float_sorted_symbolic_payloads() -> None:
    container = SymbolicList.empty("items")
    value = SymbolicValue.from_const(1)
    object.__setattr__(value, "z3_int", z3.RealVal("1.25"))
    state = VMState(stack=[container, value], pc=26)

    result = handle_common_list_append(_instr("LIST_APPEND", 1), state, OpcodeDispatcher())

    updated = result.new_states[0].stack[0]
    assert isinstance(updated, SymbolicList)
    stored = z3.simplify(z3.Select(updated.z3_array, z3.IntVal(0)))
    assert z3.is_int(stored)


def test_handle_common_map_add_rejects_missing_container() -> None:
    state = VMState(stack=["k", 1], pc=14)

    with pytest.raises(VMStateError, match="MAP_ADD"):
        handle_common_map_add(_instr("MAP_ADD", 1), state, OpcodeDispatcher())


def test_handle_common_unpack_sequence_rejects_missing_source() -> None:
    state = VMState(pc=15)

    with pytest.raises(VMStateError, match="UNPACK_SEQUENCE"):
        handle_common_unpack_sequence(_instr("UNPACK_SEQUENCE", 2), state, OpcodeDispatcher())


def test_handle_common_unpack_sequence_reports_known_too_few_values() -> None:
    build_state = VMState(stack=[1], pc=25)
    build_result = handle_common_build_list(
        _instr("BUILD_LIST", 1, offset=0), build_state, OpcodeDispatcher()
    )
    state = build_result.new_states[0].set_pc(1)

    result = handle_common_unpack_sequence(
        _instr("UNPACK_SEQUENCE", 2, offset=2), state, OpcodeDispatcher()
    )

    assert result.terminal is True
    assert result.issues[0].kind == IssueKind.VALUE_ERROR


def test_handle_common_unpack_sequence_uses_concrete_items_in_store_order() -> None:
    build_state = VMState(stack=[1, 2], pc=25)
    build_result = handle_common_build_list(
        _instr("BUILD_LIST", 2, offset=0), build_state, OpcodeDispatcher()
    )
    state = build_result.new_states[0].set_pc(1)

    result = handle_common_unpack_sequence(
        _instr("UNPACK_SEQUENCE", 2, offset=2), state, OpcodeDispatcher()
    )

    next_state = result.new_states[0]
    assert next_state.stack[-1] == 1
    assert next_state.stack[-2] == 2


def test_handle_common_unpack_ex_uses_concrete_items_in_store_order() -> None:
    state = VMState(stack=[(1, 2, 3, 4)], pc=27)

    result = handle_common_unpack_ex(
        _instr("UNPACK_EX", 0x0101, offset=2), state, OpcodeDispatcher()
    )

    next_state = result.new_states[0]
    assert next_state.stack[-1] == 1
    assert next_state.stack[-2] == [2, 3]
    assert next_state.stack[-3] == 4


def test_handle_common_unpack_ex_reports_known_too_few_values() -> None:
    state = VMState(stack=[(1,)], pc=28)

    result = handle_common_unpack_ex(
        _instr("UNPACK_EX", 0x0101, offset=2), state, OpcodeDispatcher()
    )

    assert result.terminal is True
    assert result.issues[0].kind == IssueKind.VALUE_ERROR


def test_handle_common_unpack_ex_symbolic_star_target_is_list_with_length_relation() -> None:
    source, constraint = SymbolicList.symbolic("items")
    state = VMState(stack=[source], pc=29).add_constraint(constraint)

    result = handle_common_unpack_ex(
        _instr("UNPACK_EX", 0x0101, offset=2), state, OpcodeDispatcher()
    )

    next_state = result.new_states[0]
    before = next_state.stack[-1]
    star = next_state.stack[-2]
    after = next_state.stack[-3]
    assert isinstance(before, SymbolicValue)
    assert isinstance(star, SymbolicList)
    assert isinstance(after, SymbolicValue)
    assert z3.is_true(z3.simplify(star.is_list))
    assert z3.is_true(z3.simplify(star.z3_len == source.z3_len - 2))
    assert z3.is_true(z3.simplify(before.z3_int == z3.Select(source.z3_array, z3.IntVal(0))))
    assert z3.is_true(z3.simplify(after.z3_int == z3.Select(source.z3_array, source.z3_len - 1)))


def test_handle_common_unpack_ex_generic_list_value_constrains_source_and_star_lengths() -> None:
    source_len = z3.Int("generic_len")
    source = SymbolicValue(
        _name="generic_list",
        z3_int=source_len,
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_list=z3.BoolVal(True),
        affinity_type="list",
    )
    state = VMState(stack=[source], pc=30)

    result = handle_common_unpack_ex(
        _instr("UNPACK_EX", 0x0201, offset=2), state, OpcodeDispatcher()
    )

    next_state = result.new_states[0]
    star = next_state.stack[-2]
    assert isinstance(star, SymbolicList)
    solver = z3.Solver()
    solver.add(*next_state.path_constraints)
    solver.add(star.z3_len != source_len - 3)
    assert solver.check() == z3.unsat
    too_short = z3.Solver()
    too_short.add(*next_state.path_constraints, source_len == 2)
    assert too_short.check() == z3.unsat


def test_handle_common_delete_subscr_shrinks_heap_backed_symbolic_list() -> None:
    handle, _constraint = SymbolicObject.symbolic("list_obj", 41)
    state = VMState(
        stack=[handle, 1],
        memory={41: SymbolicList.from_const([1, 2, 3])},
        pc=31,
    )

    result = handle_common_delete_subscr(
        _instr("DELETE_SUBSCR", offset=2), state, OpcodeDispatcher()
    )

    updated = result.new_states[0].memory[41]
    assert isinstance(updated, SymbolicList)
    assert updated.concrete_items == [1, 3]
    assert z3.is_true(z3.simplify(updated.z3_len == z3.IntVal(2)))


def test_handle_common_delete_subscr_mutates_concrete_list() -> None:
    items = [1, 2, 3]
    state = VMState(stack=cast("list[StackValue]", [items, -1]), pc=32)

    handle_common_delete_subscr(_instr("DELETE_SUBSCR", offset=2), state, OpcodeDispatcher())

    assert items == [1, 2]


def test_handle_common_dict_merge_update_rejects_missing_container() -> None:
    state = VMState(stack=[{"x": 1}], pc=16)

    with pytest.raises(VMStateError, match="DICT_UPDATE"):
        handle_common_dict_merge_update(_instr("DICT_UPDATE", 1, arg=1), state, OpcodeDispatcher())
