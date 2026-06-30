from __future__ import annotations

import dis
import sys
import types

import pytest

import pysymex._internal.execution.opcodes.py313.exceptions as exceptions
from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from tests.unit.execution.opcodes.py313.exception_helpers import (
    Entry,
    code_object,
    dispatcher_for,
    instr,
    instruction_by_offset,
)

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 13),
    reason="Requires Python 3.13+",
)


def test_handle_push_exc_info_terminates_impossible_direct_handler_entry() -> None:
    """A handler target cannot run without the exception-table jump payload."""
    code = code_object(
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
    dispatcher = dispatcher_for(code, [Entry(4, 34, instruction.offset, 0, False)])
    state = VMState(pc=dispatcher.offset_to_index(instruction.offset) or 0)

    result = exceptions.handle_push_exc_info(instruction, state, dispatcher)

    assert result.terminal is True
    assert result.new_states == []


def test_handle_raise_varargs_uses_exception_table_stack_shape() -> None:
    """Raised exceptions enter handlers with the stack expected by PUSH_EXC_INFO."""
    code = code_object(
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
    dispatcher = dispatcher_for(
        code,
        [Entry(instruction.offset, instruction.offset + 2, handler.offset, 0, False)],
    )
    state = VMState(stack=[ValueError], pc=0)

    result = exceptions.handle_raise_varargs(instruction, state, dispatcher)

    next_state = result.new_states[0]
    assert len(next_state.stack) == 1
    assert next_state.pc == dispatcher.offset_to_index(handler.offset)


def test_handle_push_exc_info_activates_exception_below_lasti_metadata() -> None:
    """``lasti`` metadata must not replace the active exception."""
    exc = SymbolicException.concrete(ZeroDivisionError)
    lasti = SymbolicValue.from_const(28)
    state = VMState(stack=["exit", exc, lasti], pc=0)

    exceptions.handle_push_exc_info(instr("PUSH_EXC_INFO"), state, OpcodeDispatcher())

    assert state.active_exception is exc
    assert state.stack[0] == "exit"
    assert state.stack[1] is exc
    assert isinstance(state.stack[2], SymbolicNoneType)
    assert state.stack[3] is lasti


def test_handle_reraise_uses_exception_table_cleanup_stack_shape() -> None:
    """Cleanup handlers with lasti metadata receive enough stack entries for COPY 3."""
    outer = code_object(
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
    instruction = instruction_by_offset(code, 50)
    dispatcher = dispatcher_for(code, [Entry(50, 52, 52, 1, True)])
    exc = SymbolicValue.from_const(ValueError("boom"))
    state = VMState(stack=[SymbolicValue.from_const(0), exc], pc=0)

    result = exceptions.handle_reraise(instruction, state, dispatcher)

    next_state = result.new_states[0]
    assert len(next_state.stack) == 3
    assert next_state.pc == dispatcher.offset_to_index(52)


def test_handle_reraise_keeps_modeled_exception_below_lasti_metadata() -> None:
    """A cleanup re-raise must propagate the modeled exception, not saved lasti."""
    outer = code_object(
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
    instruction = instruction_by_offset(code, 50)
    dispatcher = dispatcher_for(code, [Entry(50, 52, 52, 1, True)])
    exc = SymbolicException.concrete(ZeroDivisionError)
    state = VMState(stack=[exc, SymbolicValue.from_const(34)], pc=0)

    result = exceptions.handle_reraise(instruction, state, dispatcher)

    next_state = result.new_states[0]
    assert exc in next_state.stack


def test_handle_reraise_prefers_new_wrapped_exception_over_retained_exception() -> None:
    """A replacement exception from cleanup supersedes the older active exception."""
    outer = code_object(
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
    instruction = instruction_by_offset(code, 50)
    dispatcher = dispatcher_for(code, [Entry(50, 52, 52, 0, False)])
    original = SymbolicException.concrete(ZeroDivisionError)
    replacement, _ = SymbolicValue.symbolic("ValueError_instance")
    replacement_exc = SymbolicException.concrete(ValueError)
    replacement.attach_modeled_object(replacement_exc)
    state = VMState(stack=[original, replacement, SymbolicValue.from_const(34)], pc=0)

    result = exceptions.handle_reraise(instruction, state, dispatcher)

    assert result.new_states[0].stack == [replacement_exc]
