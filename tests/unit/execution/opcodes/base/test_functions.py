from __future__ import annotations

import dis

import pytest
import z3

from pysymex.analysis.detectors import IssueKind
from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicNone, SymbolicValue
from pysymex.core.types.containers import SymbolicObject
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.base import functions


def _instr(opname: str, argval: object = None) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval)

def test_handle_precall() -> None:
    """Test handle_precall behavior."""
    state = VMState(pc=0)
    functions.handle_precall(_instr("PRECALL"), state, OpcodeDispatcher())
    assert state.pc == 1


def test_handle_call() -> None:
    """Test handle_call behavior."""
    state = VMState(stack=[SymbolicNone()], pc=0)
    result = functions.handle_call(_instr("CALL", 0), state, OpcodeDispatcher())
    assert result.terminal is True
    assert result.issues[0].kind is IssueKind.TYPE_ERROR


def test_handle_call_kw() -> None:
    """Test handle_call_kw behavior."""
    state = VMState(stack=[SymbolicNone()], pc=0)
    result = functions.handle_call_kw(_instr("CALL_KW", 0), state, OpcodeDispatcher())
    assert result.terminal is True
    assert result.issues[0].kind is IssueKind.TYPE_ERROR


def test_handle_call_method() -> None:
    """Test handle_call_method behavior."""
    state = VMState(stack=["method_name", 1], pc=0)
    result = functions.handle_call_method(_instr("CALL_METHOD", 0), state, OpcodeDispatcher())
    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 1


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
    with pytest.raises(NameError):
        functions.handle_import_from(_instr("IMPORT_FROM", "sqrt"), state, OpcodeDispatcher())


def test_handle_import_star() -> None:
    """Test handle_import_star behavior."""
    state = VMState(stack=[1], pc=0)
    functions.handle_import_star(_instr("IMPORT_STAR"), state, OpcodeDispatcher())
    assert state.stack == []


def test_handle_load_super_attr() -> None:
    """Test handle_load_super_attr behavior."""
    state = VMState(stack=[1, 2, 3], pc=0)
    with pytest.raises(NameError):
        functions.handle_load_super_attr(_instr("LOAD_SUPER_ATTR", "x"), state, OpcodeDispatcher())


def test_handle_load_super_variants() -> None:
    """Test handle_load_super_variants behavior."""
    state = VMState(stack=[1, 2], pc=0)
    with pytest.raises(NameError):
        functions.handle_load_super_variants(
            _instr("LOAD_SUPER_METHOD", "m"), state, OpcodeDispatcher()
        )


def test_handle_set_function_attribute() -> None:
    """Test handle_set_function_attribute behavior."""
    state = VMState(stack=["attr", "func"], pc=0)
    functions.handle_set_function_attribute(
        _instr("SET_FUNCTION_ATTRIBUTE"), state, OpcodeDispatcher()
    )
    assert state.peek() == "attr"
