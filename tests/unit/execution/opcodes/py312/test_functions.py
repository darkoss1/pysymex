from __future__ import annotations

import dis

import z3

from pysymex.analysis.detectors import IssueKind
from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicNone, SymbolicValue
from pysymex.core.types.containers import SymbolicObject
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.py312 import functions


def _instr(opname: str, argval: object = None) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval)


def test_handle_call() -> None:
    """Test handle_call behavior."""
    state = VMState(stack=[SymbolicNone()], pc=0)
    result = functions.handle_call(_instr("CALL", 0), state, OpcodeDispatcher())
    assert result.terminal is True
    assert result.issues[0].kind is IssueKind.TYPE_ERROR


def test_handle_load_method() -> None:
    """Test handle_load_method behavior."""
    state = VMState(stack=[SymbolicNone()], pc=0)
    result = functions.handle_load_method(_instr("LOAD_METHOD", "x"), state, OpcodeDispatcher())
    assert result.terminal is True
    assert result.issues[0].kind is IssueKind.NULL_DEREFERENCE


def test_handle_store_attr() -> None:
    """Test handle_store_attr behavior."""
    obj = SymbolicObject("o", -1, z3.IntVal(-1), {-1})
    state = VMState(stack=[123, obj], pc=0)
    result = functions.handle_store_attr(_instr("STORE_ATTR", "a"), state, OpcodeDispatcher())
    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 1


def test_handle_delete_attr() -> None:
    """Test handle_delete_attr behavior."""
    state = VMState(stack=[1], pc=0)
    functions.handle_delete_attr(_instr("DELETE_ATTR", "a"), state, OpcodeDispatcher())
    assert state.stack == []


def test_handle_call_function_ex() -> None:
    """Test handle_call_function_ex behavior."""
    state = VMState(stack=[SymbolicValue.from_const({}), SymbolicValue.from_const([])], pc=0)
    functions.handle_call_function_ex(_instr("CALL_FUNCTION_EX", 0), state, OpcodeDispatcher())
    assert state.pc == 1


def test_handle_make_function() -> None:
    """Test handle_make_function behavior."""
    state = VMState(stack=["code"], pc=0)
    functions.handle_make_function(_instr("MAKE_FUNCTION", 0), state, OpcodeDispatcher())
    assert isinstance(state.peek(), SymbolicValue)


def test_handle_load_build_class() -> None:
    """Test handle_load_build_class behavior."""
    state = VMState(pc=0)
    functions.handle_load_build_class(_instr("LOAD_BUILD_CLASS"), state, OpcodeDispatcher())
    top = state.peek()
    assert isinstance(top, SymbolicValue)
    assert top.name == "__build_class__"


def test_handle_kw_names() -> None:
    """Test handle_kw_names behavior."""
    state = VMState(pc=0)
    functions.handle_kw_names(_instr("KW_NAMES", ("x", "y")), state, OpcodeDispatcher())
    assert state.pending_kw_names == ("x", "y")


def test_handle_import_name() -> None:
    """Test handle_import_name behavior."""
    state = VMState(stack=[0, 0], pc=0)
    functions.handle_import_name(_instr("IMPORT_NAME", "math"), state, OpcodeDispatcher())
    top = state.peek()
    assert isinstance(top, SymbolicObject)
    assert top.name == "math"


def test_handle_import_from() -> None:
    """Test handle_import_from behavior."""
    state = VMState(stack=[1], pc=0)
    functions.handle_import_from(_instr("IMPORT_FROM", "sqrt"), state, OpcodeDispatcher())


def test_handle_load_super_attr() -> None:
    """Test handle_load_super_attr behavior."""
    state = VMState(stack=[1, 2, 3], pc=0)
    functions.handle_load_super_attr(_instr("LOAD_SUPER_ATTR", "x"), state, OpcodeDispatcher())
