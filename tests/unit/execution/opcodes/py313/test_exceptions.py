from __future__ import annotations

import sys
import dis
import pytest

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 13),
    reason="Requires Python 3.13+",
)
from dataclasses import dataclass
import types


from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicValue
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.py313 import exceptions


def _instr(opname: str, argval: object = None, offset: int = 0) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval, offset=offset)


def _code_object(source: str, name: str) -> types.CodeType:
    module_code = compile(source, "<test>", "exec")
    for const in module_code.co_consts:
        if isinstance(const, types.CodeType) and const.co_name == name:
            return const
    raise AssertionError(f"missing code object {name}")


def _instruction_by_offset(code: types.CodeType, offset: int) -> dis.Instruction:
    for instruction in dis.get_instructions(code):
        if instruction.offset == offset:
            return instruction
    raise AssertionError(f"missing instruction at offset {offset}")


@dataclass(frozen=True)
class _Entry:
    start: int
    end: int
    target: int
    depth: int
    lasti: bool


def _dispatcher_for(code: types.CodeType, entries: list[object]) -> OpcodeDispatcher:
    dispatcher = OpcodeDispatcher()
    instructions = list(dis.get_instructions(code))
    dispatcher.set_instructions(instructions)
    dispatcher.set_exception_entries(entries)
    return dispatcher


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


def test_handle_push_exc_info_terminates_impossible_direct_handler_entry() -> None:
    """A handler target cannot run without the exception-table jump payload."""
    code = _code_object(
        """
def f():
    try:
        raise ValueError()
    except ValueError:
        return 1
""",
        "f",
    )
    instruction = next(i for i in dis.get_instructions(code) if i.opname == "PUSH_EXC_INFO")
    dispatcher = _dispatcher_for(code, [_Entry(4, 34, instruction.offset, 0, False)])
    state = VMState(pc=dispatcher.offset_to_index(instruction.offset) or 0)

    result = exceptions.handle_push_exc_info(instruction, state, dispatcher)

    assert result.terminal is True
    assert result.new_states == []


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
    assert len(result.issues) == 0


def test_handle_raise_varargs_uses_exception_table_stack_shape() -> None:
    """Raised exceptions enter handlers with the stack expected by PUSH_EXC_INFO."""
    code = _code_object(
        """
def f(x):
    try:
        if x:
            raise ValueError()
    except ValueError:
        return 1
    return 0
""",
        "f",
    )
    instruction = next(i for i in dis.get_instructions(code) if i.opname == "RAISE_VARARGS")
    handler = next(i for i in dis.get_instructions(code) if i.opname == "PUSH_EXC_INFO")
    dispatcher = _dispatcher_for(
        code,
        [_Entry(instruction.offset, instruction.offset + 2, handler.offset, 0, False)],
    )
    state = VMState(stack=[ValueError], pc=0)

    result = exceptions.handle_raise_varargs(instruction, state, dispatcher)

    next_state = result.new_states[0]
    assert len(next_state.stack) == 1
    assert next_state.pc == dispatcher.offset_to_index(handler.offset)


def test_handle_reraise_uses_exception_table_cleanup_stack_shape() -> None:
    """Cleanup handlers with lasti metadata receive enough stack entries for COPY 3."""
    outer = _code_object(
        """
def f():
    def g():
        try:
            yield 1
        except ValueError:
            yield 2
    return g
""",
        "f",
    )
    code = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == "g")
    instruction = _instruction_by_offset(code, 50)
    dispatcher = _dispatcher_for(code, [_Entry(50, 52, 52, 1, True)])
    exc = SymbolicValue.from_const(ValueError("boom"))
    state = VMState(stack=[SymbolicValue.from_const(0), exc], pc=0)

    result = exceptions.handle_reraise(instruction, state, dispatcher)

    next_state = result.new_states[0]
    assert len(next_state.stack) == 3
    assert next_state.pc == dispatcher.offset_to_index(52)


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
    assert len(result.issues) == 0


def test_handle_return_generator() -> None:
    """Test handle_return_generator behavior."""
    state = VMState(pc=0)
    exceptions.handle_return_generator(_instr("RETURN_GENERATOR"), state, OpcodeDispatcher())
