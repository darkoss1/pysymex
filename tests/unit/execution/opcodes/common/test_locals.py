from __future__ import annotations

import dis

import pytest

from pysymex.core.state.record import VMState
from pysymex.core.state.types import CallFrame, VMStateError, wrap_cow_dict
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.common.locals import (
    handle_common_delete_name,
    handle_common_load_const,
    handle_common_load_global,
    handle_common_load_from_dict_or_deref,
    handle_common_load_from_dict_or_globals,
    handle_common_store_deref,
    handle_common_store_fast,
    handle_common_store_fast_maybe_null,
    handle_common_store_global,
    handle_common_store_name,
)


def _instr(opname: str, argval: object = None, arg: int | None = None) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval, arg=arg)


def test_handle_common_load_global_pushes_null_below_callable() -> None:
    state = VMState(pc=19)

    result = handle_common_load_global(
        _instr("LOAD_GLOBAL", "range", arg=1),
        state,
        OpcodeDispatcher(),
    )

    next_state = result.new_states[0]
    assert result.terminal is False
    assert len(next_state.stack) == 2
    assert isinstance(next_state.stack[0], SymbolicNone)
    assert isinstance(next_state.stack[1], SymbolicValue)
    assert getattr(next_state.stack[1], "model_name") == "range"


def test_handle_common_load_const_preserves_literal_tuple_for_pattern_consumers() -> None:
    state = VMState(pc=20)

    result = handle_common_load_const(
        _instr("LOAD_CONST", ("fallback", 0)),
        state,
        OpcodeDispatcher(),
    )

    assert result.new_states[0].peek() == ("fallback", 0)


def test_handle_common_store_fast_rejects_missing_value() -> None:
    state = VMState(pc=20)

    with pytest.raises(VMStateError, match="STORE_FAST"):
        handle_common_store_fast(_instr("STORE_FAST", "x"), state, OpcodeDispatcher())


def test_handle_common_store_global_rejects_missing_value() -> None:
    state = VMState(pc=21)

    with pytest.raises(VMStateError, match="STORE_GLOBAL"):
        handle_common_store_global(_instr("STORE_GLOBAL", "x"), state, OpcodeDispatcher())


def test_handle_common_store_name_rejects_missing_value() -> None:
    state = VMState(pc=22)

    with pytest.raises(VMStateError, match="STORE_NAME"):
        handle_common_store_name(_instr("STORE_NAME", "x"), state, OpcodeDispatcher())


def test_handle_common_store_name_mirrors_root_exec_namespace_to_globals() -> None:
    state = VMState(stack=[21], pc=30)

    result = handle_common_store_name(_instr("STORE_NAME", "value"), state, OpcodeDispatcher())

    next_state = result.new_states[0]
    assert next_state.local_vars["value"] == 21
    assert next_state.global_vars["value"] == 21


def test_handle_common_store_name_keeps_nested_namespace_local_only() -> None:
    frame = CallFrame("class-body", 1, wrap_cow_dict({}), 0)
    state = VMState(stack=[21], call_stack=[frame], pc=31)

    result = handle_common_store_name(_instr("STORE_NAME", "value"), state, OpcodeDispatcher())

    next_state = result.new_states[0]
    assert next_state.local_vars["value"] == 21
    assert "value" not in next_state.global_vars


def test_handle_common_delete_name_removes_root_exec_global_alias() -> None:
    state = VMState(local_vars={"value": 21}, global_vars={"value": 21}, pc=32)

    result = handle_common_delete_name(_instr("DELETE_NAME", "value"), state, OpcodeDispatcher())

    next_state = result.new_states[0]
    assert "value" not in next_state.local_vars
    assert "value" not in next_state.global_vars


def test_handle_common_delete_name_keeps_nested_global_binding() -> None:
    frame = CallFrame("class-body", 1, wrap_cow_dict({}), 0)
    state = VMState(
        local_vars={"value": 21},
        global_vars={"value": 34},
        call_stack=[frame],
        pc=33,
    )

    result = handle_common_delete_name(_instr("DELETE_NAME", "value"), state, OpcodeDispatcher())

    next_state = result.new_states[0]
    assert "value" not in next_state.local_vars
    assert next_state.global_vars["value"] == 34


def test_handle_common_store_deref_rejects_missing_value() -> None:
    state = VMState(pc=23)

    with pytest.raises(VMStateError, match="STORE_DEREF"):
        handle_common_store_deref(_instr("STORE_DEREF", "x"), state, OpcodeDispatcher())


def test_handle_common_store_fast_maybe_null_rejects_missing_value() -> None:
    state = VMState(pc=24)

    with pytest.raises(VMStateError, match="STORE_FAST_MAYBE_NULL"):
        handle_common_store_fast_maybe_null(
            _instr("STORE_FAST_MAYBE_NULL", "x"),
            state,
            OpcodeDispatcher(),
        )


def test_handle_common_load_from_dict_or_deref_rejects_missing_namespace() -> None:
    state = VMState(pc=25)

    with pytest.raises(VMStateError, match="LOAD_FROM_DICT_OR_DEREF"):
        handle_common_load_from_dict_or_deref(
            _instr("LOAD_FROM_DICT_OR_DEREF", "x"),
            state,
            OpcodeDispatcher(),
        )


def test_handle_common_load_from_dict_or_globals_rejects_missing_namespace() -> None:
    state = VMState(pc=26)

    with pytest.raises(VMStateError, match="LOAD_FROM_DICT_OR_GLOBALS"):
        handle_common_load_from_dict_or_globals(
            _instr("LOAD_FROM_DICT_OR_GLOBALS", "x"),
            state,
            OpcodeDispatcher(),
        )
