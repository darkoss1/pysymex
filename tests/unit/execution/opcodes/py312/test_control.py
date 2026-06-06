from __future__ import annotations

import dis

import z3

from pysymex.core.state.types import CallFrame
from pysymex.core.state.record import VMState
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.py312 import control


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


def test_handle_return_const_truncates_callee_stack_before_pushing_result() -> None:
    dispatcher = OpcodeDispatcher()
    caller_instructions = [_instr("NOP", offset=0), _instr("NOP", offset=4)]
    dispatcher.set_instructions(caller_instructions)
    state = VMState(stack=[SymbolicValue.from_const(9), SymbolicValue.from_const(99)], pc=0)
    state = state.push_call(
        CallFrame(
            function_name="callee",
            return_pc=1,
            local_vars=state.local_vars,
            stack_depth=1,
            caller_instructions=list(caller_instructions),
        )
    )

    result = control.handle_return_const(_instr("RETURN_CONST", 5), state, dispatcher)

    next_state = result.new_states[0]
    assert [value.value for value in next_state.stack if isinstance(value, SymbolicValue)] == [9, 5]


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


def test_handle_jump() -> None:
    """Test handle_jump behavior."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("NOP", offset=0), _instr("NOP", offset=8)])
    state = VMState(pc=0)
    control.handle_jump(_instr("JUMP_FORWARD", 8, offset=0), state, dispatcher)
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


def test_handle_get_len() -> None:
    """Test handle_get_len behavior."""
    state = VMState(stack=["abc"], pc=0)
    control.handle_get_len(_instr("GET_LEN"), state, OpcodeDispatcher())
    assert isinstance(state.peek(), SymbolicValue)


def test_handle_call_intrinsic_1() -> None:
    """Test handle_call_intrinsic_1 behavior."""
    state = VMState(stack=[1], pc=0)
    control.handle_call_intrinsic_1(_instr("CALL_INTRINSIC_1", 5), state, OpcodeDispatcher())
    assert state.peek() == 1


def test_handle_call_intrinsic_1_list_to_tuple_concrete_list() -> None:
    """LIST_TO_TUPLE consumes one list and pushes tuple-modeled items."""
    state = VMState(stack=[[1, 2]], pc=7)
    result = control.handle_call_intrinsic_1(
        _instr("CALL_INTRINSIC_1", 6), state, OpcodeDispatcher()
    )

    next_state = result.new_states[0]
    assert len(next_state.stack) == 1
    tuple_value = next_state.peek()
    assert isinstance(tuple_value, SymbolicList)
    assert tuple_value.name == "tuple_7"
    assert tuple_value.concrete_items == [1, 2]
    assert z3.is_true(z3.simplify(tuple_value.z3_len == z3.IntVal(2)))


def test_handle_call_intrinsic_1_list_to_tuple_resolves_heap_backed_list() -> None:
    """LIST_TO_TUPLE must not lose concrete list payloads hidden behind handles."""
    handle, _constraint = SymbolicObject.symbolic("list_obj", 41)
    storage = SymbolicList.from_const([3, 4])
    state = VMState(stack=[handle], memory={41: storage}, pc=8)
    result = control.handle_call_intrinsic_1(
        _instr("CALL_INTRINSIC_1", 6), state, OpcodeDispatcher()
    )

    tuple_value = result.new_states[0].peek()
    assert isinstance(tuple_value, SymbolicList)
    assert tuple_value.name == "tuple_8"
    assert tuple_value.concrete_items == [3, 4]
    assert z3.is_true(z3.simplify(tuple_value.z3_len == z3.IntVal(2)))


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


def test_handle_match_sequence() -> None:
    """Test handle_match_sequence behavior."""
    state = VMState(stack=[[1]], pc=0)
    control.handle_match_sequence(_instr("MATCH_SEQUENCE"), state, OpcodeDispatcher())
    assert isinstance(state.peek(), SymbolicValue)


def test_handle_match_keys() -> None:
    """Test handle_match_keys behavior."""
    state = VMState(stack=[{}, ("a",)], pc=0)
    res = control.handle_match_keys(_instr("MATCH_KEYS"), state, OpcodeDispatcher())
    assert res is not None


def test_handle_match_class() -> None:
    """Test handle_match_class behavior."""
    state = VMState(stack=[1, int, ()], pc=0)
    res = control.handle_match_class(_instr("MATCH_CLASS", 0), state, OpcodeDispatcher())
    assert res is not None
