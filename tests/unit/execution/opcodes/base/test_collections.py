from __future__ import annotations

import dis

import pytest
import z3

from pysymex.analysis.detectors import IssueKind
from pysymex.core.state import VMState
from pysymex.core.types.containers import SymbolicDict, SymbolicList, SymbolicObject
from pysymex.core.types.scalars import SymbolicString, SymbolicValue
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.base import collections


def _instr(opname: str, argval: object = None, offset: int = 0) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval, offset=offset)


def test_handle_build_list() -> None:
    """Test handle_build_list behavior."""
    state = VMState(stack=[1, 2], pc=0)
    result = collections.handle_build_list(_instr("BUILD_LIST", 2), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].peek(), SymbolicObject)


def test_handle_build_tuple() -> None:
    """Test handle_build_tuple behavior."""
    state = VMState(stack=[1, 2], pc=0)
    result = collections.handle_build_tuple(_instr("BUILD_TUPLE", 2), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].peek(), SymbolicList)


def test_handle_build_set() -> None:
    """Test handle_build_set behavior."""
    state = VMState(stack=[1, 2], pc=0)
    with pytest.raises(NameError):
        collections.handle_build_set(_instr("BUILD_SET", 2), state, OpcodeDispatcher())


def test_handle_build_map() -> None:
    """Test handle_build_map behavior."""
    state = VMState(stack=["k", 1], pc=0)
    result = collections.handle_build_map(_instr("BUILD_MAP", 1), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].peek(), SymbolicDict)


def test_handle_build_const_key_map() -> None:
    """Test handle_build_const_key_map behavior."""
    state = VMState(stack=[1, ("k",)], pc=0)
    result = collections.handle_build_const_key_map(
        _instr("BUILD_CONST_KEY_MAP", 1),
        state,
        OpcodeDispatcher(),
    )
    assert isinstance(result.new_states[0].peek(), SymbolicDict)


def test_handle_build_string() -> None:
    """Test handle_build_string behavior."""
    state = VMState(stack=["a", "b"], pc=0)
    result = collections.handle_build_string(_instr("BUILD_STRING", 2), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].peek(), SymbolicString)


def test_handle_build_slice() -> None:
    """Test handle_build_slice behavior."""
    state = VMState(stack=[0, 2], pc=0)
    with pytest.raises(NameError):
        collections.handle_build_slice(_instr("BUILD_SLICE", 2), state, OpcodeDispatcher())


def test_handle_list_extend() -> None:
    """Test handle_list_extend behavior."""
    sym_list, _ = SymbolicList.symbolic("l")
    state = VMState(stack=[sym_list, [2, 3]], pc=0)
    result = collections.handle_list_extend(_instr("LIST_EXTEND", 1), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].stack[0], SymbolicList)


def test_handle_collection_update() -> None:
    """Test handle_collection_update behavior."""
    sym_dict, _ = SymbolicDict.symbolic("d")
    state = VMState(stack=[sym_dict, {"k": 1}], pc=0)
    result = collections.handle_collection_update(_instr("DICT_UPDATE", 1), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].stack[0], SymbolicDict)


def test_handle_list_append() -> None:
    """Test handle_list_append behavior."""
    sym_list, _ = SymbolicList.symbolic("l")
    state = VMState(stack=[sym_list, 5], pc=0)
    result = collections.handle_list_append(_instr("LIST_APPEND", 1), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].stack[0], SymbolicList)


def test_handle_set_add() -> None:
    """Test handle_set_add behavior."""
    state = VMState(stack=[1], pc=0)
    result = collections.handle_set_add(_instr("SET_ADD", 1), state, OpcodeDispatcher())
    assert result.new_states[0].pc == 1


def test_handle_map_add() -> None:
    """Test handle_map_add behavior."""
    sym_dict, _ = SymbolicDict.symbolic("d")
    state = VMState(stack=[sym_dict, SymbolicString.from_const("k"), 7], pc=0)
    result = collections.handle_map_add(_instr("MAP_ADD", 1), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].stack[0], SymbolicDict)


def test_handle_binary_subscr() -> None:
    """Test handle_binary_subscr behavior."""
    sym_list, _ = SymbolicList.symbolic("items")
    sym_list.z3_len = z3.IntVal(1)
    state = VMState(stack=[sym_list, SymbolicValue.from_const(0)], pc=0)
    result = collections.handle_binary_subscr(_instr("BINARY_SUBSCR"), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].peek(), SymbolicValue)


def test_handle_store_subscr() -> None:
    """Test handle_store_subscr behavior."""
    state = VMState(stack=[1, None, 0], pc=0)
    result = collections.handle_store_subscr(_instr("STORE_SUBSCR"), state, OpcodeDispatcher())
    assert result.terminal is True
    assert any(issue.kind is IssueKind.NULL_DEREFERENCE for issue in result.issues)


def test_handle_delete_subscr() -> None:
    """Test handle_delete_subscr behavior."""
    state = VMState(stack=[[1, 2], 0], pc=0)
    result = collections.handle_delete_subscr(_instr("DELETE_SUBSCR"), state, OpcodeDispatcher())
    assert result.new_states[0].pc == 1


def test_handle_binary_slice() -> None:
    """Test handle_binary_slice behavior."""
    state = VMState(stack=[SymbolicString.from_const("abc"), 0, 2], pc=0)
    result = collections.handle_binary_slice(_instr("BINARY_SLICE"), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].peek(), SymbolicString)


def test_handle_store_slice() -> None:
    """Test handle_store_slice behavior."""
    state = VMState(stack=[[], 0, 1, [9]], pc=0)
    result = collections.handle_store_slice(_instr("STORE_SLICE"), state, OpcodeDispatcher())
    assert result.new_states[0].pc == 1


def test_handle_unpack_sequence() -> None:
    """Test handle_unpack_sequence behavior."""
    sym_list, _ = SymbolicList.symbolic("seq")
    sym_list.z3_len = z3.IntVal(2)
    state = VMState(stack=[sym_list], pc=0)
    result = collections.handle_unpack_sequence(_instr("UNPACK_SEQUENCE", 2), state, OpcodeDispatcher())
    assert len(result.new_states[0].stack) == 2


def test_handle_unpack_ex() -> None:
    """Test handle_unpack_ex behavior."""
    state = VMState(stack=[(1, 2, 3)], pc=0)
    with pytest.raises(NameError):
        collections.handle_unpack_ex(_instr("UNPACK_EX", 0x0101), state, OpcodeDispatcher())


def test_handle_format_value() -> None:
    """Test handle_format_value behavior."""
    state = VMState(stack=[12], pc=0)
    result = collections.handle_format_value(_instr("FORMAT_VALUE", 0), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].peek(), SymbolicString)


def test_handle_convert_value() -> None:
    """Test handle_convert_value behavior."""
    state = VMState(stack=[12], pc=0)
    result = collections.handle_convert_value(_instr("CONVERT_VALUE"), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].peek(), SymbolicString)


def test_handle_format_simple() -> None:
    """Test handle_format_simple behavior."""
    state = VMState(stack=[12], pc=0)
    result = collections.handle_format_simple(_instr("FORMAT_SIMPLE"), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].peek(), SymbolicString)


def test_handle_format_with_spec() -> None:
    """Test handle_format_with_spec behavior."""
    state = VMState(stack=[12, ":d"], pc=0)
    result = collections.handle_format_with_spec(_instr("FORMAT_WITH_SPEC"), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].peek(), SymbolicString)
