from __future__ import annotations

import dis


from pysymex.core.state import UNBOUND, VMState
from pysymex.core.types.scalars import SymbolicValue
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.py312 import locals


def _instr(opname: str, argval: object = None, arg: int = 0) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval, arg=arg)


def test_handle_load_const() -> None:
    """Test handle_load_const behavior."""
    state = VMState(pc=0)
    locals.handle_load_const(_instr("LOAD_CONST", 10), state, OpcodeDispatcher())
    assert isinstance(state.peek(), SymbolicValue)


def test_handle_load_fast() -> None:
    """Test handle_load_fast behavior."""
    state = VMState(local_vars={"x": 7}, pc=0)
    locals.handle_load_fast(_instr("LOAD_FAST", "x"), state, OpcodeDispatcher())
    assert state.peek() == 7


def test_handle_store_fast() -> None:
    """Test handle_store_fast behavior."""
    state = VMState(stack=[11], pc=0)
    locals.handle_store_fast(_instr("STORE_FAST", "x"), state, OpcodeDispatcher())
    assert state.local_vars["x"] == 11


def test_handle_delete_fast() -> None:
    """Test handle_delete_fast behavior."""
    state = VMState(local_vars={"x": 3}, pc=0)
    locals.handle_delete_fast(_instr("DELETE_FAST", "x"), state, OpcodeDispatcher())
    assert "x" not in state.local_vars


def test_handle_load_global() -> None:
    """Test handle_load_global behavior."""
    state = VMState(global_vars={"g": 5}, pc=0)
    locals.handle_load_global(_instr("LOAD_GLOBAL", "g"), state, OpcodeDispatcher())
    assert state.peek() == 5


def test_handle_load_closure() -> None:
    """Test handle_load_closure behavior."""
    state = VMState(pc=0)
    locals.handle_load_closure(_instr("LOAD_CLOSURE", 0), state, OpcodeDispatcher())
    assert state.pc == 1


def test_handle_copy_free_vars() -> None:
    """Test handle_copy_free_vars behavior."""
    state = VMState(pc=0)
    locals.handle_copy_free_vars(_instr("COPY_FREE_VARS", 0), state, OpcodeDispatcher())
    assert state.pc == 1


def test_handle_load_fast_check() -> None:
    """Test handle_load_fast_check behavior."""
    state = VMState(local_vars={"x": 7}, pc=0)
    locals.handle_load_fast_check(_instr("LOAD_FAST_CHECK", "x"), state, OpcodeDispatcher())
    assert state.peek() == 7


def test_handle_store_global() -> None:
    """Test handle_store_global behavior."""
    state = VMState(stack=[13], pc=0)
    locals.handle_store_global(_instr("STORE_GLOBAL", "g"), state, OpcodeDispatcher())
    assert state.global_vars["g"] == 13


def test_handle_delete_global() -> None:
    """Test handle_delete_global behavior."""
    state = VMState(global_vars={"g": 9}, pc=0)
    locals.handle_delete_global(_instr("DELETE_GLOBAL", "g"), state, OpcodeDispatcher())
    assert "g" not in state.global_vars


def test_handle_load_name() -> None:
    """Test handle_load_name behavior."""
    state = VMState(local_vars={"n": 4}, pc=0)
    locals.handle_load_name(_instr("LOAD_NAME", "n"), state, OpcodeDispatcher())
    assert state.peek() == 4


def test_handle_store_name() -> None:
    """Test handle_store_name behavior."""
    state = VMState(stack=[21], pc=0)
    locals.handle_store_name(_instr("STORE_NAME", "n"), state, OpcodeDispatcher())
    assert state.local_vars["n"] == 21


def test_handle_delete_name() -> None:
    """Test handle_delete_name behavior."""
    state = VMState(local_vars={"n": 1}, pc=0)
    locals.handle_delete_name(_instr("DELETE_NAME", "n"), state, OpcodeDispatcher())
    assert "n" not in state.local_vars


def test_handle_load_deref() -> None:
    """Test handle_load_deref behavior."""
    state = VMState(local_vars={"c": 6}, pc=0)
    locals.handle_load_deref(_instr("LOAD_DEREF", "c"), state, OpcodeDispatcher())
    assert state.peek() == 6


def test_handle_store_deref() -> None:
    """Test handle_store_deref behavior."""
    state = VMState(stack=[31], pc=0)
    locals.handle_store_deref(_instr("STORE_DEREF", "c"), state, OpcodeDispatcher())
    assert state.local_vars["c"] == 31


def test_handle_cell_ops() -> None:
    """Test handle_cell_ops behavior."""
    state = VMState(pc=10)
    locals.handle_cell_ops(_instr("MAKE_CELL"), state, OpcodeDispatcher())
    assert state.pc == 11


def test_handle_delete_deref() -> None:
    """Test handle_delete_deref behavior."""
    state = VMState(local_vars={"c": 2}, pc=0)
    locals.handle_delete_deref(_instr("DELETE_DEREF", "c"), state, OpcodeDispatcher())
    assert "c" not in state.local_vars


def test_handle_load_fast_and_clear() -> None:
    """Test handle_load_fast_and_clear behavior."""
    state = VMState(local_vars={"x": 15}, pc=0)
    locals.handle_load_fast_and_clear(_instr("LOAD_FAST_AND_CLEAR", "x"), state, OpcodeDispatcher())
    assert state.peek() == 15
    assert state.get_local("x") is UNBOUND


def test_handle_load_from_dict_or_deref() -> None:
    """Test handle_load_from_dict_or_deref behavior."""
    state = VMState(stack=[{}], local_vars={"x": 44}, pc=0)
    locals.handle_load_from_dict_or_deref(
        _instr("LOAD_FROM_DICT_OR_DEREF", "x"), state, OpcodeDispatcher()
    )
    assert state.peek() == 44


def test_handle_load_from_dict_or_globals() -> None:
    """Test handle_load_from_dict_or_globals behavior."""
    state = VMState(stack=[{}], global_vars={"g": 55}, pc=0)
    locals.handle_load_from_dict_or_globals(
        _instr("LOAD_FROM_DICT_OR_GLOBALS", "g"), state, OpcodeDispatcher()
    )
    assert state.peek() == 55


def test_handle_load_locals() -> None:
    """Test handle_load_locals behavior."""
    state = VMState(local_vars={"x": 1}, pc=0)
    locals.handle_load_locals(_instr("LOAD_LOCALS"), state, OpcodeDispatcher())


def test_handle_setup_annotations() -> None:
    """Test handle_setup_annotations behavior."""
    state = VMState(pc=4)
    locals.handle_setup_annotations(_instr("SETUP_ANNOTATIONS"), state, OpcodeDispatcher())
    assert state.pc == 5
