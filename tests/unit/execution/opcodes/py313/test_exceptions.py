from __future__ import annotations

import dis


from pysymex.analysis.detectors import IssueKind
from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicValue
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.py313 import exceptions


def _instr(opname: str, argval: object = None, offset: int = 0) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval, offset=offset)


def test_try_block_can_raise() -> None:
    """Test try_block_can_raise behavior."""
    items = [_instr("LOAD_CONST"), _instr("CALL")]
    assert exceptions.try_block_can_raise(items) is True


def test_handle_setup_finally() -> None:
    """Test handle_setup_finally behavior."""
    state = VMState(pc=0)
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("NOP", offset=0), _instr("NOP", offset=10)])
    exceptions.handle_setup_finally(_instr("SETUP_FINALLY", 10, offset=0), state, dispatcher)
    assert len(state.block_stack) == 1


def test_handle_pop_block() -> None:
    """Test handle_pop_block behavior."""
    state = VMState(pc=0)
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("NOP", offset=0), _instr("NOP", offset=8)])
    exceptions.handle_setup_finally(_instr("SETUP_FINALLY", 8, offset=0), state, dispatcher)
    exceptions.handle_pop_block(_instr("POP_BLOCK"), state, dispatcher)
    assert len(state.block_stack) == 0


def test_handle_push_exc_info() -> None:
    """Test handle_push_exc_info behavior."""
    state = VMState(stack=["exc"], pc=0)
    exceptions.handle_push_exc_info(_instr("PUSH_EXC_INFO"), state, OpcodeDispatcher())
    assert len(state.stack) == 2


def test_handle_pop_except() -> None:
    """Test handle_pop_except behavior."""
    state = VMState(stack=["e"], pc=0)
    exceptions.handle_pop_except(_instr("POP_EXCEPT"), state, OpcodeDispatcher())
    assert state.stack == []


def test_handle_check_exc_match() -> None:
    """Test handle_check_exc_match behavior."""
    base = SymbolicValue.from_const(1)
    exc = SymbolicValue(
        _name="ValueError",
        z3_int=base.z3_int,
        is_int=base.is_int,
        z3_bool=base.z3_bool,
        is_bool=base.is_bool,
    )
    state = VMState(stack=[exc, ValueError], pc=0)
    exceptions.handle_check_exc_match(_instr("CHECK_EXC_MATCH"), state, OpcodeDispatcher())
    top = state.peek()
    assert isinstance(top, SymbolicValue)


def test_handle_cleanup_throw() -> None:
    """Test handle_cleanup_throw behavior."""
    state = VMState(pc=2)
    exceptions.handle_cleanup_throw(_instr("CLEANUP_THROW"), state, OpcodeDispatcher())
    assert state.pc == 3


def test_handle_reraise() -> None:
    """Test handle_reraise behavior."""
    state = VMState(stack=["exc"], pc=0)
    result = exceptions.handle_reraise(_instr("RERAISE", 0), state, OpcodeDispatcher())
    assert result.terminal is True
    assert result.issues[0].kind is IssueKind.EXCEPTION


def test_handle_with_except_start() -> None:
    """Test handle_with_except_start behavior."""
    state = VMState(pc=0)
    exceptions.handle_with_except_start(_instr("WITH_EXCEPT_START"), state, OpcodeDispatcher())


def test_handle_before_with() -> None:
    """Test handle_before_with behavior."""
    state = VMState(stack=[1], pc=0)
    exceptions.handle_before_with(_instr("BEFORE_WITH"), state, OpcodeDispatcher())


def test_handle_before_async_with() -> None:
    """Test handle_before_async_with behavior."""
    state = VMState(stack=[1], pc=0)
    exceptions.handle_before_async_with(_instr("BEFORE_ASYNC_WITH"), state, OpcodeDispatcher())


def test_handle_end_async_for() -> None:
    """Test handle_end_async_for behavior."""
    state = VMState(stack=[1, 2], pc=0)
    exceptions.handle_end_async_for(_instr("END_ASYNC_FOR"), state, OpcodeDispatcher())
    assert state.stack == []


def test_handle_get_aiter() -> None:
    """Test handle_get_aiter behavior."""
    state = VMState(stack=[1], pc=0)
    exceptions.handle_get_aiter(_instr("GET_AITER"), state, OpcodeDispatcher())


def test_handle_get_anext() -> None:
    """Test handle_get_anext behavior."""
    state = VMState(pc=0)
    exceptions.handle_get_anext(_instr("GET_ANEXT"), state, OpcodeDispatcher())


def test_handle_get_awaitable() -> None:
    """Test handle_get_awaitable behavior."""
    state = VMState(stack=[1], pc=0)
    exceptions.handle_get_awaitable(_instr("GET_AWAITABLE"), state, OpcodeDispatcher())


def test_handle_send() -> None:
    """Test handle_send behavior."""
    state = VMState(stack=[1, 2], pc=0)
    exceptions.handle_send(_instr("SEND"), state, OpcodeDispatcher())


def test_handle_yield_value() -> None:
    """Test handle_yield_value behavior."""
    state = VMState(stack=[1], pc=0)
    exceptions.handle_yield_value(_instr("YIELD_VALUE"), state, OpcodeDispatcher())


def test_handle_end_send() -> None:
    """Test handle_end_send behavior."""
    state = VMState(stack=[1, 2], pc=0)
    exceptions.handle_end_send(_instr("END_SEND"), state, OpcodeDispatcher())
    assert len(state.stack) == 1


def test_handle_get_yield_from_iter() -> None:
    """Test handle_get_yield_from_iter behavior."""
    state = VMState(stack=[1], pc=0)
    exceptions.handle_get_yield_from_iter(_instr("GET_YIELD_FROM_ITER"), state, OpcodeDispatcher())


def test_handle_check_eg_match() -> None:
    """Test handle_check_eg_match behavior."""
    state = VMState(stack=[1, 2], pc=0)
    exceptions.handle_check_eg_match(_instr("CHECK_EG_MATCH"), state, OpcodeDispatcher())


def test_handle_setup_cleanup() -> None:
    """Test handle_setup_cleanup behavior."""
    state = VMState(pc=0)
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("NOP", offset=0), _instr("NOP", offset=4)])
    exceptions.handle_setup_cleanup(_instr("SETUP_CLEANUP", 4, offset=0), state, dispatcher)
    assert len(state.block_stack) == 1


def test_handle_interpreter_exit() -> None:
    """Test handle_interpreter_exit behavior."""
    result = exceptions.handle_interpreter_exit(
        _instr("INTERPRETER_EXIT"), VMState(), OpcodeDispatcher()
    )
    assert result.terminal is True


def test_handle_raise_varargs() -> None:
    """Test handle_raise_varargs behavior."""
    state = VMState(stack=[SymbolicValue.from_const(1)], pc=0)
    result = exceptions.handle_raise_varargs(
        _instr("RAISE_VARARGS", 1, offset=0), state, OpcodeDispatcher()
    )
    assert result.terminal is True
    assert len(result.issues) == 1


def test_handle_return_generator() -> None:
    """Test handle_return_generator behavior."""
    state = VMState(pc=0)
    exceptions.handle_return_generator(_instr("RETURN_GENERATOR"), state, OpcodeDispatcher())
