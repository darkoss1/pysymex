from __future__ import annotations

import dis
from collections.abc import Callable

import z3

import pysymex._internal.execution.opcodes.py311.control as control
from pysymex._internal.core.classes.classes import SymbolicClass
from pysymex._internal.core.classes.registry import class_registry
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.core.types.truthiness import get_truthy_expr
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def _instr(opname: str, argval: object = None, offset: int = 0) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval, offset=offset)


def _false_bool(_self: object) -> bool:
    return False


def _true_bool(_self: object) -> bool:
    return True


def _modeled_bool_value(class_name: str, method: Callable[[object], bool]) -> SymbolicValue:
    modeled_cls = class_registry.register_class(SymbolicClass(class_name))
    modeled_cls.add_method("__bool__", method)
    value = SymbolicValue.from_const(1)
    value.attach_modeled_object(class_registry.instantiate(modeled_cls))
    return value


def test_handle_no_op() -> None:
    """Test handle_no_op behavior."""
    state = VMState(pc=2)
    control.handle_no_op(_instr("NOP"), state, OpcodeDispatcher())
    assert state.pc == 3


def test_get_truthy_expr() -> None:
    """Test get_truthy_expr behavior."""
    assert z3.is_true(simplify_expr(get_truthy_expr(1)))
    assert z3.is_true(simplify_expr(z3.Not(get_truthy_expr(0))))


def test_handle_return_value() -> None:
    """Test handle_return_value behavior."""
    state = VMState(stack=[1], pc=0)
    result = control.handle_return_value(_instr("RETURN_VALUE"), state, OpcodeDispatcher())
    assert result.terminal is True


def test_handle_jump() -> None:
    """Test handle_jump behavior."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("NOP", offset=0), _instr("NOP", offset=8)])
    state = VMState(pc=0)
    control.handle_jump(_instr("JUMP_FORWARD", 8, offset=0), state, dispatcher)
    assert state.pc == 1


def test_handle_jump_or_pop() -> None:
    """Test handle_jump_or_pop behavior."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("NOP", offset=0), _instr("NOP", offset=8)])
    state = VMState(stack=[True], pc=0)
    result = control.handle_jump_or_pop(
        _instr("JUMP_IF_TRUE_OR_POP", 8, offset=0), state, dispatcher
    )
    assert len(result.new_states) >= 1


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
    state = VMState(stack=[()], pc=0)
    result = control.handle_for_iter(_instr("FOR_ITER", 4), state, dispatcher)
    assert len(result.new_states) == 1


def test_handle_get_iter() -> None:
    """Test handle_get_iter behavior."""
    state = VMState(stack=[[1, 2]], pc=0)
    control.handle_get_iter(_instr("GET_ITER"), state, OpcodeDispatcher())
    assert len(state.stack) == 1


def test_handle_get_len() -> None:
    """Test handle_get_len behavior."""
    state = VMState(stack=["abc"], pc=0)
    control.handle_get_len(_instr("GET_LEN"), state, OpcodeDispatcher())
    assert isinstance(state.peek(), SymbolicValue)


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


def test_handle_jump_backward() -> None:
    """Test handle_jump behavior with JUMP_BACKWARD."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("NOP", offset=0), _instr("NOP", offset=8)])
    state = VMState(pc=0)
    control.handle_jump(_instr("JUMP_BACKWARD", 8, offset=0), state, dispatcher)
    assert state.pc == 1


def test_handle_jump_backward_no_interrupt() -> None:
    """Test handle_jump behavior with JUMP_BACKWARD_NO_INTERRUPT."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("NOP", offset=0), _instr("NOP", offset=8)])
    state = VMState(pc=0)
    control.handle_jump(_instr("JUMP_BACKWARD_NO_INTERRUPT", 8, offset=0), state, dispatcher)
    assert state.pc == 1


def test_handle_jump_if_false_or_pop() -> None:
    """Test handle_jump_if_false_or_pop behavior."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("NOP", offset=0), _instr("NOP", offset=8)])
    state = VMState(stack=[False], pc=0)
    result = control.handle_jump_or_pop(
        _instr("JUMP_IF_FALSE_OR_POP", 8, offset=0), state, dispatcher
    )
    assert len(result.new_states) >= 1


def test_handle_jump_if_false_or_pop_retains_modeled_operand_after_false_bool() -> None:
    original = _modeled_bool_value("_FalseShortCircuit", _false_bool)
    dispatcher = OpcodeDispatcher()
    instr = _instr("JUMP_IF_FALSE_OR_POP", 8, offset=0)
    dispatcher.set_instructions([instr, _instr("NOP", offset=4), _instr("NOP", offset=8)])

    dispatched = control.handle_jump_or_pop(instr, VMState(stack=[original], pc=0), dispatcher)
    returned = control.handle_return_value(
        _instr("RETURN_VALUE"),
        dispatched.new_states[0].push(SymbolicValue.from_const(False)),
        dispatcher,
    )

    assert len(returned.new_states) == 1
    assert returned.new_states[0].pc == 2
    assert returned.new_states[0].peek() is original


def test_handle_jump_if_false_or_pop_drops_modeled_operand_after_true_bool() -> None:
    original = _modeled_bool_value("_TrueFallthrough", _true_bool)
    dispatcher = OpcodeDispatcher()
    instr = _instr("JUMP_IF_FALSE_OR_POP", 8, offset=0)
    dispatcher.set_instructions([instr, _instr("NOP", offset=4), _instr("NOP", offset=8)])

    dispatched = control.handle_jump_or_pop(instr, VMState(stack=[original], pc=0), dispatcher)
    returned = control.handle_return_value(
        _instr("RETURN_VALUE"),
        dispatched.new_states[0].push(SymbolicValue.from_const(True)),
        dispatcher,
    )

    assert len(returned.new_states) == 1
    assert returned.new_states[0].pc == 1
    assert returned.new_states[0].stack == []


def test_handle_resume() -> None:
    """Test handle_resume behavior (no-op, same as NOP)."""
    state = VMState(pc=0)
    control.handle_no_op(_instr("RESUME"), state, OpcodeDispatcher())
    assert state.pc == 1


def test_handle_print_expr() -> None:
    """Test handle_print_expr behavior."""
    state = VMState(stack=[42], pc=0)
    control.handle_print_expr(_instr("PRINT_EXPR"), state, OpcodeDispatcher())
    assert state.pc == 1
