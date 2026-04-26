from __future__ import annotations

import dis

from pysymex.core.state import VMState
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.py312 import instrumentation


def _instr(opname: str) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname)


def test_handle_instrumented_call() -> None:
    """Test handle_instrumented_call behavior."""
    state = VMState(pc=5)
    result = instrumentation.handle_instrumented_call(
        _instr("INSTRUMENTED_CALL"), state, OpcodeDispatcher()
    )
    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 6


def test_handle_instrumented_call_function_ex() -> None:
    """Test handle_instrumented_call_function_ex behavior."""
    state = VMState(pc=10)
    result = instrumentation.handle_instrumented_call_function_ex(
        _instr("INSTRUMENTED_CALL_FUNCTION_EX"), state, OpcodeDispatcher()
    )
    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 11


def test_handle_instrumented_end_for() -> None:
    """Test handle_instrumented_end_for behavior."""
    state = VMState(pc=15)
    result = instrumentation.handle_instrumented_end_for(
        _instr("INSTRUMENTED_END_FOR"), state, OpcodeDispatcher()
    )
    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 16


def test_handle_instrumented_end_send() -> None:
    """Test handle_instrumented_end_send behavior."""
    state = VMState(pc=20)
    result = instrumentation.handle_instrumented_end_send(
        _instr("INSTRUMENTED_END_SEND"), state, OpcodeDispatcher()
    )
    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 21


def test_handle_instrumented_for_iter() -> None:
    """Test handle_instrumented_for_iter behavior."""
    state = VMState(pc=25)
    result = instrumentation.handle_instrumented_for_iter(
        _instr("INSTRUMENTED_FOR_ITER"), state, OpcodeDispatcher()
    )
    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 26


def test_handle_instrumented_instruction() -> None:
    """Test handle_instrumented_instruction behavior."""
    state = VMState(pc=30)
    result = instrumentation.handle_instrumented_instruction(
        _instr("INSTRUMENTED_INSTRUCTION"), state, OpcodeDispatcher()
    )
    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 31


def test_handle_instrumented_jump_backward() -> None:
    """Test handle_instrumented_jump_backward behavior."""
    state = VMState(pc=35)
    result = instrumentation.handle_instrumented_jump_backward(
        _instr("INSTRUMENTED_JUMP_BACKWARD"), state, OpcodeDispatcher()
    )
    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 36


def test_handle_instrumented_jump_forward() -> None:
    """Test handle_instrumented_jump_forward behavior."""
    state = VMState(pc=40)
    result = instrumentation.handle_instrumented_jump_forward(
        _instr("INSTRUMENTED_JUMP_FORWARD"), state, OpcodeDispatcher()
    )
    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 41


def test_handle_instrumented_line() -> None:
    """Test handle_instrumented_line behavior."""
    state = VMState(pc=45)
    result = instrumentation.handle_instrumented_line(
        _instr("INSTRUMENTED_LINE"), state, OpcodeDispatcher()
    )
    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 46


def test_handle_instrumented_load_super_attr() -> None:
    """Test handle_instrumented_load_super_attr behavior."""
    state = VMState(pc=50)
    result = instrumentation.handle_instrumented_load_super_attr(
        _instr("INSTRUMENTED_LOAD_SUPER_ATTR"), state, OpcodeDispatcher()
    )
    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 51


def test_handle_instrumented_pop_jump_if_false() -> None:
    """Test handle_instrumented_pop_jump_if_false behavior."""
    state = VMState(pc=55)
    result = instrumentation.handle_instrumented_pop_jump_if_false(
        _instr("INSTRUMENTED_POP_JUMP_IF_FALSE"), state, OpcodeDispatcher()
    )
    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 56


def test_handle_instrumented_pop_jump_if_none() -> None:
    """Test handle_instrumented_pop_jump_if_none behavior."""
    state = VMState(pc=60)
    result = instrumentation.handle_instrumented_pop_jump_if_none(
        _instr("INSTRUMENTED_POP_JUMP_IF_NONE"), state, OpcodeDispatcher()
    )
    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 61


def test_handle_instrumented_pop_jump_if_not_none() -> None:
    """Test handle_instrumented_pop_jump_if_not_none behavior."""
    state = VMState(pc=65)
    result = instrumentation.handle_instrumented_pop_jump_if_not_none(
        _instr("INSTRUMENTED_POP_JUMP_IF_NOT_NONE"), state, OpcodeDispatcher()
    )
    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 66


def test_handle_instrumented_pop_jump_if_true() -> None:
    """Test handle_instrumented_pop_jump_if_true behavior."""
    state = VMState(pc=70)
    result = instrumentation.handle_instrumented_pop_jump_if_true(
        _instr("INSTRUMENTED_POP_JUMP_IF_TRUE"), state, OpcodeDispatcher()
    )
    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 71


def test_handle_instrumented_resume() -> None:
    """Test handle_instrumented_resume behavior."""
    state = VMState(pc=75)
    result = instrumentation.handle_instrumented_resume(
        _instr("INSTRUMENTED_RESUME"), state, OpcodeDispatcher()
    )
    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 76


def test_handle_instrumented_return_const() -> None:
    """Test handle_instrumented_return_const behavior."""
    state = VMState(pc=80)
    result = instrumentation.handle_instrumented_return_const(
        _instr("INSTRUMENTED_RETURN_CONST"), state, OpcodeDispatcher()
    )
    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 81


def test_handle_instrumented_return_value() -> None:
    """Test handle_instrumented_return_value behavior."""
    state = VMState(pc=85)
    result = instrumentation.handle_instrumented_return_value(
        _instr("INSTRUMENTED_RETURN_VALUE"), state, OpcodeDispatcher()
    )
    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 86


def test_handle_instrumented_yield_value() -> None:
    """Test handle_instrumented_yield_value behavior."""
    state = VMState(pc=90)
    result = instrumentation.handle_instrumented_yield_value(
        _instr("INSTRUMENTED_YIELD_VALUE"), state, OpcodeDispatcher()
    )
    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 91
