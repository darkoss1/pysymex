from __future__ import annotations

from typing import cast

import z3

from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.opcodes.py311.control import (
    handle_match_class,
    handle_match_keys,
    handle_match_mapping,
    handle_match_sequence,
)
from tests.unit.execution.opcodes.py313.control_helpers import instr


def test_handle_match_mapping() -> None:
    """Test handle_match_mapping behavior."""
    state = VMState(stack=[{}], pc=0)
    handle_match_mapping(instr("MATCH_MAPPING"), state, OpcodeDispatcher())
    assert isinstance(state.peek(), SymbolicValue)


def test_handle_match_mapping_rejects_plain_symbolic_object() -> None:
    """Plain objects do not match mapping patterns in CPython."""
    subject, _constraint = SymbolicObject.symbolic("obj", 7)
    state = VMState(stack=[subject], pc=0)
    handle_match_mapping(instr("MATCH_MAPPING"), state, OpcodeDispatcher())
    result = state.peek()
    assert isinstance(result, SymbolicValue)
    assert z3.is_false(simplify_expr(result.z3_bool))


def test_handle_match_mapping_accepts_heap_backed_symbolic_dict() -> None:
    """SymbolicObject handles backed by dict storage still match mapping patterns."""
    subject, _constraint = SymbolicObject.symbolic("dict_obj", 8)
    state = VMState(stack=[subject], memory={8: SymbolicDict.empty()}, pc=0)
    handle_match_mapping(instr("MATCH_MAPPING"), state, OpcodeDispatcher())
    result = state.peek()
    assert isinstance(result, SymbolicValue)
    assert z3.is_true(simplify_expr(result.z3_bool))


def test_handle_match_sequence() -> None:
    """Test handle_match_sequence behavior."""
    state = VMState(stack=[[1]], pc=0)
    handle_match_sequence(instr("MATCH_SEQUENCE"), state, OpcodeDispatcher())
    assert isinstance(state.peek(), SymbolicValue)


def test_handle_match_sequence_rejects_plain_symbolic_object() -> None:
    """Plain objects do not match sequence patterns in CPython."""
    subject, _constraint = SymbolicObject.symbolic("obj", 9)
    state = VMState(stack=[subject], pc=0)
    handle_match_sequence(instr("MATCH_SEQUENCE"), state, OpcodeDispatcher())
    result = state.peek()
    assert isinstance(result, SymbolicValue)
    assert z3.is_false(simplify_expr(result.z3_bool))


def test_handle_match_sequence_accepts_heap_backed_symbolic_list() -> None:
    """SymbolicObject handles backed by list storage still match sequence patterns."""
    subject, _constraint = SymbolicObject.symbolic("list_obj", 10)
    state = VMState(stack=[subject], memory={10: SymbolicList.empty()}, pc=0)
    handle_match_sequence(instr("MATCH_SEQUENCE"), state, OpcodeDispatcher())
    result = state.peek()
    assert isinstance(result, SymbolicValue)
    assert z3.is_true(simplify_expr(result.z3_bool))


def test_handle_match_keys() -> None:
    """Test handle_match_keys behavior."""
    state = VMState(stack=[{}, ("a",)], pc=0)
    res = handle_match_keys(instr("MATCH_KEYS"), state, OpcodeDispatcher())
    assert res is not None


def test_handle_match_keys_rejects_missing_key_on_heap_backed_symbolic_dict() -> None:
    """Heap-backed dict handles must not satisfy impossible mapping-key patterns."""
    subject, _constraint = SymbolicObject.symbolic("dict_obj", 12)
    state = VMState(stack=[subject, ("missing",)], memory={12: SymbolicDict.empty()}, pc=0)
    handle_match_keys(instr("MATCH_KEYS"), state, OpcodeDispatcher())
    result = state.peek()
    assert isinstance(result, SymbolicNone)


def test_handle_match_keys_accepts_present_key_on_heap_backed_symbolic_dict() -> None:
    """Heap-backed dict handles should use stored key membership facts."""
    subject, _constraint = SymbolicObject.symbolic("dict_obj", 13)
    state = VMState(
        stack=[subject, ("present",)],
        memory={13: SymbolicDict.from_const({"present": 1})},
        pc=0,
    )
    handle_match_keys(instr("MATCH_KEYS"), state, OpcodeDispatcher())
    result = state.peek()
    assert isinstance(result, tuple)
    assert len(cast("tuple[object, ...]", result)) == 1


def test_handle_match_class() -> None:
    """Test handle_match_class behavior."""
    state = VMState(stack=[1, int, ()], pc=0)
    res = handle_match_class(instr("MATCH_CLASS", 0), state, OpcodeDispatcher())
    assert res is not None
