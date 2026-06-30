from __future__ import annotations

import dis
from typing import Any

import pytest

from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.opcodes.common.formatting import handle_common_format_value


def _instr(arg: int | None = 0) -> dis.Instruction:
    import inspect

    sig = inspect.signature(dis.Instruction)
    kwargs: dict[str, Any] = {
        "opname": "FORMAT_VALUE",
        "opcode": 0,
        "arg": arg,
        "argval": arg,
        "argrepr": "" if arg is None else str(arg),
        "offset": 0,
        "starts_line": None,
    }
    if "start_offset" in sig.parameters:
        kwargs["start_offset"] = 0
    if "line_number" in sig.parameters:
        kwargs["line_number"] = None
    if "is_jump_target" in sig.parameters:
        kwargs["is_jump_target"] = False
    if "positions" in sig.parameters:
        kwargs["positions"] = None
    return dis.Instruction(**kwargs)


def test_handle_common_format_value_rejects_invalid_flags() -> None:
    state = VMState().push(42)

    result = handle_common_format_value(_instr(0x08), state, OpcodeDispatcher())

    assert result.issues[0].kind == IssueKind.RUNTIME_ERROR
    assert "Invalid FORMAT_VALUE flags" in result.issues[0].message


def test_handle_common_format_value_formats_concrete_spec() -> None:
    state = VMState().push(42).push("04d")

    result = handle_common_format_value(_instr(0x04), state, OpcodeDispatcher())

    assert result.new_states[0].stack == ["0042"]


def test_handle_common_format_value_rejects_non_string_spec() -> None:
    state = VMState().push(42).push(1)

    result = handle_common_format_value(_instr(0x04), state, OpcodeDispatcher())

    assert result.issues[0].kind == IssueKind.TYPE_ERROR
    assert "format spec must be str" in result.issues[0].message


def test_handle_common_format_value_symbolic_value_returns_symbolic_string() -> None:
    value, _ = SymbolicString.symbolic("value")
    state = VMState().push(value)

    result = handle_common_format_value(_instr(0), state, OpcodeDispatcher())

    assert isinstance(result.new_states[0].stack[0], SymbolicString)


def test_handle_common_format_value_underflow_propagates() -> None:
    state = VMState()

    with pytest.raises(RuntimeError, match="Stack underflow"):
        handle_common_format_value(_instr(0), state, OpcodeDispatcher())
