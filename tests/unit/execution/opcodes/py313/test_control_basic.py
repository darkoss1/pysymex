from __future__ import annotations

import dis
import sys

import z3

from pysymex.analysis.detectors.detector.types import IssueKind
from pysymex.core.state.record import VMState
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.py313 import control
from tests.unit.execution.opcodes.py313.control_helpers import instr


def test_handle_no_op() -> None:
    """Test handle_no_op behavior."""
    state = VMState(pc=2)
    control.handle_no_op(instr("NOP"), state, OpcodeDispatcher())
    assert state.pc == 3


def test_get_truthy_expr() -> None:
    """Test get_truthy_expr behavior."""
    assert z3.is_true(z3.simplify(control.get_truthy_expr(1)))
    assert z3.is_true(z3.simplify(z3.Not(control.get_truthy_expr(0))))


def test_handle_return_value() -> None:
    """Test handle_return_value behavior."""
    state = VMState(stack=[1], pc=0)
    result = control.handle_return_value(instr("RETURN_VALUE"), state, OpcodeDispatcher())
    assert result.terminal is True


def test_handle_return_const() -> None:
    """Test handle_return_const behavior."""
    state = VMState(pc=0)
    result = control.handle_return_const(instr("RETURN_CONST", 5), state, OpcodeDispatcher())
    assert result.terminal is True


def test_handle_jump() -> None:
    """Test handle_jump behavior with JUMP."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([instr("NOP", offset=0), instr("NOP", offset=10)])
    state = VMState(pc=0)
    control.handle_jump(instr("JUMP", 10, offset=0), state, dispatcher)
    assert state.pc == 1


def test_handle_jump_backward() -> None:
    """Test handle_jump behavior with JUMP_BACKWARD."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([instr("NOP", offset=0), instr("NOP", offset=10)])
    state = VMState(pc=0)
    control.handle_jump(instr("JUMP_BACKWARD", 10, offset=0), state, dispatcher)
    assert state.pc == 1


def test_handle_jump_backward_no_interrupt() -> None:
    """Test handle_jump behavior with JUMP_BACKWARD_NO_INTERRUPT."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([instr("NOP", offset=0), instr("NOP", offset=10)])
    state = VMState(pc=0)
    control.handle_jump(instr("JUMP_BACKWARD_NO_INTERRUPT", 10, offset=0), state, dispatcher)
    assert state.pc == 1


def test_handle_jump_no_interrupt() -> None:
    """Test handle_jump behavior with JUMP_NO_INTERRUPT."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([instr("NOP", offset=0), instr("NOP", offset=10)])
    state = VMState(pc=0)
    control.handle_jump(instr("JUMP_NO_INTERRUPT", 10, offset=0), state, dispatcher)
    assert state.pc == 1


def test_handle_resume() -> None:
    """Test handle_resume behavior (no-op, same as NOP)."""
    state = VMState(pc=0)
    control.handle_no_op(instr("RESUME"), state, OpcodeDispatcher())
    assert state.pc == 1


def test_handle_reserved() -> None:
    """Test handle_reserved behavior (no-op, same as NOP)."""
    state = VMState(pc=0)
    control.handle_nop_and_reserved(instr("RESERVED"), state, OpcodeDispatcher())
    assert state.pc == 1


def test_handle_exit_init_check() -> None:
    """Test handle_exit_init_check behavior."""
    state = VMState(stack=[SymbolicValue.from_const(1)], pc=0)
    control.handle_exit_init_check(instr("EXIT_INIT_CHECK"), state, OpcodeDispatcher())
    assert state.pc == 1


def test_handle_pop_jump_if_none() -> None:
    """Test handle_pop_jump_if_none behavior."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([instr("NOP", offset=0), instr("NOP", offset=10)])
    state = VMState(stack=[SymbolicNone()], pc=0)
    control.handle_pop_jump_if_none(instr("POP_JUMP_IF_NONE", 10, offset=0), state, dispatcher)
    assert state.pc == 1


def test_handle_pop_jump_if_not_none() -> None:
    """Test handle_pop_jump_if_not_none behavior."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([instr("NOP", offset=0), instr("NOP", offset=10)])
    state = VMState(stack=[1], pc=0)
    control.handle_pop_jump_if_not_none(
        instr("POP_JUMP_IF_NOT_NONE", 10, offset=0), state, dispatcher
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
    result = control.handle_raise_varargs(instr("RAISE_VARARGS", 1), state, OpcodeDispatcher())
    assert result.terminal is True


def test_handle_load_assertion_error() -> None:
    """Test handle_load_assertion_error behavior."""
    state = VMState(pc=0)
    control.handle_load_assertion_error(instr("LOAD_ASSERTION_ERROR"), state, OpcodeDispatcher())
    assert isinstance(state.peek(), SymbolicValue)


def test_handle_for_iter() -> None:
    """Test handle_for_iter behavior."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([instr("NOP", offset=0), instr("NOP", offset=4)])
    state = VMState(stack=[], pc=0)
    result = control.handle_for_iter(instr("FOR_ITER", 4), state, dispatcher)
    assert len(result.new_states) == 1


def test_handle_get_iter() -> None:
    """Test handle_get_iter behavior."""
    state = VMState(stack=[[1, 2]], pc=0)
    control.handle_get_iter(instr("GET_ITER"), state, OpcodeDispatcher())
    assert len(state.stack) == 1


def test_handle_end_for() -> None:
    """Test handle_end_for behavior."""
    state = VMState(stack=[1, 2], pc=0)
    control.handle_end_for(instr("END_FOR"), state, OpcodeDispatcher())
    assert state.stack == [1]


def test_handle_to_bool() -> None:
    """Test handle_to_bool behavior."""
    state = VMState(stack=[1], pc=0)
    control.handle_to_bool(instr("TO_BOOL"), state, OpcodeDispatcher())
    assert isinstance(state.peek(), SymbolicValue)


def test_handle_get_len() -> None:
    """Test handle_get_len behavior."""
    state = VMState(stack=["abc"], pc=0)
    control.handle_get_len(instr("GET_LEN"), state, OpcodeDispatcher())
    assert isinstance(state.peek(), SymbolicValue)


def test_handle_get_len_uses_concrete_list_length() -> None:
    """GET_LEN must not make concrete non-empty lists look empty."""
    state = VMState(stack=[[1, 2, 3]], pc=0)
    control.handle_get_len(instr("GET_LEN"), state, OpcodeDispatcher())
    result = state.peek()
    assert isinstance(result, SymbolicValue)
    assert z3.is_true(z3.simplify(result.z3_int == z3.IntVal(3)))


def test_handle_get_len_resolves_heap_backed_symbolic_list() -> None:
    """GET_LEN should use symbolic container length through object handles."""
    subject, _constraint = SymbolicObject.symbolic("list_obj", 11)
    storage = SymbolicList.empty("items")
    state = VMState(stack=[subject], memory={11: storage}, pc=0)
    control.handle_get_len(instr("GET_LEN"), state, OpcodeDispatcher())
    result = state.peek()
    assert isinstance(result, SymbolicValue)
    assert z3.is_true(z3.simplify(result.z3_int == storage.z3_len))


def test_handle_enter_executor() -> None:
    """Test handle_enter_executor behavior."""
    state = VMState(pc=0)
    control.handle_enter_executor(instr("ENTER_EXECUTOR"), state, OpcodeDispatcher())
    assert state.pc == 1


def test_handle_call_intrinsic_1() -> None:
    """Test handle_call_intrinsic_1 behavior."""
    state = VMState(stack=[1], pc=0)
    control.handle_call_intrinsic_1(instr("CALL_INTRINSIC_1", 5), state, OpcodeDispatcher())
    assert state.peek() == 1


def test_handle_call_intrinsic_1_list_to_tuple_concrete_list() -> None:
    """LIST_TO_TUPLE consumes one list and pushes tuple-modeled items."""
    state = VMState(stack=[[1, 2]], pc=7)
    result = control.handle_call_intrinsic_1(
        instr("CALL_INTRINSIC_1", 6), state, OpcodeDispatcher()
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
        instr("CALL_INTRINSIC_1", 6), state, OpcodeDispatcher()
    )

    tuple_value = result.new_states[0].peek()
    assert isinstance(tuple_value, SymbolicList)
    assert tuple_value.name == "tuple_8"
    assert tuple_value.concrete_items == [3, 4]
    assert z3.is_true(z3.simplify(tuple_value.z3_len == z3.IntVal(2)))


def test_cpython_313_unary_positive_uses_call_intrinsic_1() -> None:
    """CPython 3.13 lowers unary plus to CALL_INTRINSIC_1."""
    if sys.version_info[:2] != (3, 13):
        return
    namespace: dict[str, object] = {}
    exec(compile("def f(x):\n    return +x\n", "<unary-positive>", "exec"), namespace)
    func = namespace["f"]
    assert callable(func)
    instructions = list(dis.get_instructions(func))
    assert any(item.opname == "CALL_INTRINSIC_1" and item.argval == 5 for item in instructions)


def test_cpython_313_starred_tuple_uses_list_to_tuple_intrinsic() -> None:
    """CPython 3.13 lowers starred tuple construction to LIST_TO_TUPLE intrinsic."""
    if sys.version_info[:2] != (3, 13):
        return
    namespace: dict[str, object] = {}
    exec(compile("def f(a):\n    return (*a,)\n", "<list-to-tuple>", "exec"), namespace)
    func = namespace["f"]
    assert callable(func)
    instructions = list(dis.get_instructions(func))
    assert any(item.opname == "CALL_INTRINSIC_1" and item.argval == 6 for item in instructions)


def test_handle_call_intrinsic_1_unary_positive_reports_string_type_error() -> None:
    """Python 3.13 unary-positive intrinsic must not pass through strings."""
    state = VMState(stack=["text"], pc=0)
    result = control.handle_call_intrinsic_1(
        instr("CALL_INTRINSIC_1", 5), state, OpcodeDispatcher()
    )
    assert result.terminal is True
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]


def test_handle_call_intrinsic_2() -> None:
    """Test handle_call_intrinsic_2 behavior."""
    state = VMState(stack=[1, 2], pc=0)
    control.handle_call_intrinsic_2(instr("CALL_INTRINSIC_2", 1), state, OpcodeDispatcher())
    assert state.peek() == 1
