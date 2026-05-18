from __future__ import annotations

import dis

import z3

from pysymex.core.state import VMState
from pysymex.core.types import SymbolicDict, SymbolicList, SymbolicObject
from pysymex.core.types.scalars import SymbolicNone, SymbolicValue
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.py313 import control


def _instr(opname: str, argval: object = None, offset: int = 0) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval, offset=offset)


def test_handle_no_op() -> None:
    """Test handle_no_op behavior."""
    state = VMState(pc=2)
    control.handle_no_op(_instr("NOP"), state, OpcodeDispatcher())
    assert state.pc == 3


def test_get_truthy_expr() -> None:
    """Test get_truthy_expr behavior."""
    assert z3.is_true(z3.simplify(control.get_truthy_expr(1)))
    assert z3.is_true(z3.simplify(z3.Not(control.get_truthy_expr(0))))


def test_handle_return_value() -> None:
    """Test handle_return_value behavior."""
    state = VMState(stack=[1], pc=0)
    result = control.handle_return_value(_instr("RETURN_VALUE"), state, OpcodeDispatcher())
    assert result.terminal is True


def test_handle_return_const() -> None:
    """Test handle_return_const behavior."""
    state = VMState(pc=0)
    result = control.handle_return_const(_instr("RETURN_CONST", 5), state, OpcodeDispatcher())
    assert result.terminal is True


def test_handle_jump() -> None:
    """Test handle_jump behavior with JUMP."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("NOP", offset=0), _instr("NOP", offset=10)])
    state = VMState(pc=0)
    control.handle_jump(_instr("JUMP", 10, offset=0), state, dispatcher)
    assert state.pc == 1


def test_handle_jump_backward() -> None:
    """Test handle_jump behavior with JUMP_BACKWARD."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("NOP", offset=0), _instr("NOP", offset=10)])
    state = VMState(pc=0)
    control.handle_jump(_instr("JUMP_BACKWARD", 10, offset=0), state, dispatcher)
    assert state.pc == 1


def test_handle_jump_backward_no_interrupt() -> None:
    """Test handle_jump behavior with JUMP_BACKWARD_NO_INTERRUPT."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("NOP", offset=0), _instr("NOP", offset=10)])
    state = VMState(pc=0)
    control.handle_jump(_instr("JUMP_BACKWARD_NO_INTERRUPT", 10, offset=0), state, dispatcher)
    assert state.pc == 1


def test_handle_jump_no_interrupt() -> None:
    """Test handle_jump behavior with JUMP_NO_INTERRUPT."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("NOP", offset=0), _instr("NOP", offset=10)])
    state = VMState(pc=0)
    control.handle_jump(_instr("JUMP_NO_INTERRUPT", 10, offset=0), state, dispatcher)
    assert state.pc == 1


def test_handle_resume() -> None:
    """Test handle_resume behavior (no-op, same as NOP)."""
    state = VMState(pc=0)
    control.handle_no_op(_instr("RESUME"), state, OpcodeDispatcher())
    assert state.pc == 1


def test_handle_reserved() -> None:
    """Test handle_reserved behavior (no-op, same as NOP)."""
    state = VMState(pc=0)
    control.handle_nop_and_reserved(_instr("RESERVED"), state, OpcodeDispatcher())
    assert state.pc == 1


def test_handle_exit_init_check() -> None:
    """Test handle_exit_init_check behavior."""
    state = VMState(stack=[SymbolicValue.from_const(1)], pc=0)
    control.handle_exit_init_check(_instr("EXIT_INIT_CHECK"), state, OpcodeDispatcher())
    assert state.pc == 1


def test_handle_pop_jump_if_none() -> None:
    """Test handle_pop_jump_if_none behavior."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("NOP", offset=0), _instr("NOP", offset=10)])
    state = VMState(stack=[SymbolicNone()], pc=0)
    control.handle_pop_jump_if_none(_instr("POP_JUMP_IF_NONE", 10, offset=0), state, dispatcher)
    assert state.pc == 1


def test_handle_pop_jump_if_not_none() -> None:
    """Test handle_pop_jump_if_not_none behavior."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("NOP", offset=0), _instr("NOP", offset=10)])
    state = VMState(stack=[1], pc=0)
    control.handle_pop_jump_if_not_none(
        _instr("POP_JUMP_IF_NOT_NONE", 10, offset=0), state, dispatcher
    )
    assert state.pc == 1


def test_handle_raise_varargs() -> None:
    """Test handle_raise_varargs behavior."""
    marker = SymbolicValue.from_const(0)
    marker = SymbolicValue(
        _name="NotImplementedError",
        z3_int=marker.z3_int,
        is_int=marker.is_int,
        z3_bool=marker.z3_bool,
        is_bool=marker.is_bool,
    )
    state = VMState(stack=[marker], pc=0)
    result = control.handle_raise_varargs(_instr("RAISE_VARARGS", 1), state, OpcodeDispatcher())
    assert result.terminal is True


def test_handle_load_assertion_error() -> None:
    """Test handle_load_assertion_error behavior."""
    state = VMState(pc=0)
    control.handle_load_assertion_error(_instr("LOAD_ASSERTION_ERROR"), state, OpcodeDispatcher())
    assert isinstance(state.peek(), SymbolicValue)


def test_handle_for_iter() -> None:
    """Test handle_for_iter behavior."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("NOP", offset=0), _instr("NOP", offset=4)])
    state = VMState(stack=[], pc=0)
    result = control.handle_for_iter(_instr("FOR_ITER", 4), state, dispatcher)
    assert len(result.new_states) == 1


def test_handle_get_iter() -> None:
    """Test handle_get_iter behavior."""
    state = VMState(stack=[[1, 2]], pc=0)
    control.handle_get_iter(_instr("GET_ITER"), state, OpcodeDispatcher())
    assert len(state.stack) == 1


def test_handle_end_for() -> None:
    """Test handle_end_for behavior."""
    state = VMState(stack=[1, 2], pc=0)
    control.handle_end_for(_instr("END_FOR"), state, OpcodeDispatcher())
    assert state.stack == [1]


def test_handle_to_bool() -> None:
    """Test handle_to_bool behavior."""
    state = VMState(stack=[1], pc=0)
    control.handle_to_bool(_instr("TO_BOOL"), state, OpcodeDispatcher())
    assert isinstance(state.peek(), SymbolicValue)


def test_handle_get_len() -> None:
    """Test handle_get_len behavior."""
    state = VMState(stack=["abc"], pc=0)
    control.handle_get_len(_instr("GET_LEN"), state, OpcodeDispatcher())
    assert isinstance(state.peek(), SymbolicValue)


def test_handle_get_len_uses_concrete_list_length() -> None:
    """GET_LEN must not make concrete non-empty lists look empty."""
    state = VMState(stack=[[1, 2, 3]], pc=0)

    control.handle_get_len(_instr("GET_LEN"), state, OpcodeDispatcher())

    result = state.peek()
    assert isinstance(result, SymbolicValue)
    assert z3.is_true(z3.simplify(result.z3_int == z3.IntVal(3)))


def test_handle_get_len_resolves_heap_backed_symbolic_list() -> None:
    """GET_LEN should use symbolic container length through object handles."""
    subject, _constraint = SymbolicObject.symbolic("list_obj", 11)
    storage = SymbolicList.empty("items")
    state = VMState(stack=[subject], memory={11: storage}, pc=0)

    control.handle_get_len(_instr("GET_LEN"), state, OpcodeDispatcher())

    result = state.peek()
    assert isinstance(result, SymbolicValue)
    assert z3.is_true(z3.simplify(result.z3_int == storage.z3_len))


def test_handle_enter_executor() -> None:
    """Test handle_enter_executor behavior."""
    state = VMState(pc=0)
    control.handle_enter_executor(_instr("ENTER_EXECUTOR"), state, OpcodeDispatcher())
    assert state.pc == 1


def test_handle_call_intrinsic_1() -> None:
    """Test handle_call_intrinsic_1 behavior."""
    state = VMState(stack=[1], pc=0)
    control.handle_call_intrinsic_1(_instr("CALL_INTRINSIC_1", 5), state, OpcodeDispatcher())
    assert state.peek() == 1


def test_handle_call_intrinsic_2() -> None:
    """Test handle_call_intrinsic_2 behavior."""
    state = VMState(stack=[1, 2], pc=0)
    control.handle_call_intrinsic_2(_instr("CALL_INTRINSIC_2", 1), state, OpcodeDispatcher())
    assert state.peek() == 1


def test_handle_match_mapping() -> None:
    """Test handle_match_mapping behavior."""
    state = VMState(stack=[{}], pc=0)
    control.handle_match_mapping(_instr("MATCH_MAPPING"), state, OpcodeDispatcher())
    assert isinstance(state.peek(), SymbolicValue)


def test_handle_match_mapping_rejects_plain_symbolic_object() -> None:
    """Plain objects do not match mapping patterns in CPython."""
    subject, _constraint = SymbolicObject.symbolic("obj", 7)
    state = VMState(stack=[subject], pc=0)

    control.handle_match_mapping(_instr("MATCH_MAPPING"), state, OpcodeDispatcher())

    result = state.peek()
    assert isinstance(result, SymbolicValue)
    assert z3.is_false(z3.simplify(result.z3_bool))


def test_handle_match_mapping_accepts_heap_backed_symbolic_dict() -> None:
    """SymbolicObject handles backed by dict storage still match mapping patterns."""
    subject, _constraint = SymbolicObject.symbolic("dict_obj", 8)
    state = VMState(stack=[subject], memory={8: SymbolicDict.empty()}, pc=0)

    control.handle_match_mapping(_instr("MATCH_MAPPING"), state, OpcodeDispatcher())

    result = state.peek()
    assert isinstance(result, SymbolicValue)
    assert z3.is_true(z3.simplify(result.z3_bool))


def test_handle_match_sequence() -> None:
    """Test handle_match_sequence behavior."""
    state = VMState(stack=[[1]], pc=0)
    control.handle_match_sequence(_instr("MATCH_SEQUENCE"), state, OpcodeDispatcher())
    assert isinstance(state.peek(), SymbolicValue)


def test_handle_match_sequence_rejects_plain_symbolic_object() -> None:
    """Plain objects do not match sequence patterns in CPython."""
    subject, _constraint = SymbolicObject.symbolic("obj", 9)
    state = VMState(stack=[subject], pc=0)

    control.handle_match_sequence(_instr("MATCH_SEQUENCE"), state, OpcodeDispatcher())

    result = state.peek()
    assert isinstance(result, SymbolicValue)
    assert z3.is_false(z3.simplify(result.z3_bool))


def test_handle_match_sequence_accepts_heap_backed_symbolic_list() -> None:
    """SymbolicObject handles backed by list storage still match sequence patterns."""
    subject, _constraint = SymbolicObject.symbolic("list_obj", 10)
    state = VMState(stack=[subject], memory={10: SymbolicList.empty()}, pc=0)

    control.handle_match_sequence(_instr("MATCH_SEQUENCE"), state, OpcodeDispatcher())

    result = state.peek()
    assert isinstance(result, SymbolicValue)
    assert z3.is_true(z3.simplify(result.z3_bool))


def test_handle_match_keys() -> None:
    """Test handle_match_keys behavior."""
    state = VMState(stack=[{}, ("a",)], pc=0)
    res = control.handle_match_keys(_instr("MATCH_KEYS"), state, OpcodeDispatcher())
    assert res is not None


def test_handle_match_keys_rejects_missing_key_on_heap_backed_symbolic_dict() -> None:
    """Heap-backed dict handles must not satisfy impossible mapping-key patterns."""
    subject, _constraint = SymbolicObject.symbolic("dict_obj", 12)
    state = VMState(stack=[subject, ("missing",)], memory={12: SymbolicDict.empty()}, pc=0)

    control.handle_match_keys(_instr("MATCH_KEYS"), state, OpcodeDispatcher())

    result = state.peek()
    assert isinstance(result, SymbolicValue)
    assert z3.is_false(z3.simplify(result.z3_bool))


def test_handle_match_keys_accepts_present_key_on_heap_backed_symbolic_dict() -> None:
    """Heap-backed dict handles should use stored key membership facts."""
    subject, _constraint = SymbolicObject.symbolic("dict_obj", 13)
    state = VMState(
        stack=[subject, ("present",)],
        memory={13: SymbolicDict.from_const({"present": 1})},
        pc=0,
    )

    control.handle_match_keys(_instr("MATCH_KEYS"), state, OpcodeDispatcher())

    result = state.peek()
    assert isinstance(result, SymbolicValue)
    assert z3.is_true(z3.simplify(result.z3_bool))


def test_handle_match_class() -> None:
    """Test handle_match_class behavior."""
    state = VMState(stack=[1, int, ()], pc=0)
    res = control.handle_match_class(_instr("MATCH_CLASS", 0), state, OpcodeDispatcher())
    assert res is not None
