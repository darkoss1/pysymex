from __future__ import annotations

import dis
import sys

import pytest

from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicString, SymbolicValue
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.py313.formatting import (
    handle_convert_value,
    handle_format_simple,
    handle_format_with_spec,
)

pytestmark = pytest.mark.skipif(sys.version_info < (3, 13), reason="Python 3.13 required")


def _get_instr(code: str, opname: str) -> dis.Instruction:
    """Get the first instruction with the given opname from the compiled code."""
    for instr in dis.get_instructions(compile(code, "<test>", "exec")):
        if instr.opname == opname:
            return instr
    raise ValueError(f"Opcode {opname} not found")


class TestFormatSimple:
    def test_underflow(self) -> None:
        """Test FORMAT_SIMPLE underflow behavior."""
        state = VMState()
        instr = _get_instr("f'{1}'", "FORMAT_SIMPLE")
        with pytest.raises(RuntimeError, match="Stack underflow"):
            handle_format_simple(instr, state, OpcodeDispatcher())

    def test_symbolic_value(self) -> None:
        """Test FORMAT_SIMPLE with a symbolic value."""
        sym_val, _ = SymbolicString.symbolic("test")
        state = VMState().push(sym_val)
        instr = _get_instr("f'{1}'", "FORMAT_SIMPLE")
        result = handle_format_simple(instr, state, OpcodeDispatcher())
        assert len(result.new_states[0].stack) == 1
        assert isinstance(result.new_states[0].stack[0], SymbolicString)

    def test_int_value(self) -> None:
        """Test FORMAT_SIMPLE with an integer value."""
        state = VMState().push(42)
        instr = _get_instr("f'{1}'", "FORMAT_SIMPLE")
        result = handle_format_simple(instr, state, OpcodeDispatcher())
        assert result.new_states[0].stack[0] == "42"

    def test_unsupported_value(self) -> None:
        """Test FORMAT_SIMPLE with an unsupported type."""
        state = VMState().push(SymbolicValue.from_const(object()))
        instr = _get_instr("f'{1}'", "FORMAT_SIMPLE")
        result = handle_format_simple(instr, state, OpcodeDispatcher())
        assert isinstance(result.new_states[0].stack[0], SymbolicString)


class TestFormatWithSpec:
    def test_underflow(self) -> None:
        """Test FORMAT_WITH_SPEC underflow behavior."""
        state = VMState()
        instr = _get_instr("f'{1:d}'", "FORMAT_WITH_SPEC")
        with pytest.raises(RuntimeError, match="Stack underflow"):
            handle_format_with_spec(instr, state, OpcodeDispatcher())

    def test_symbolic_value(self) -> None:
        """Test FORMAT_WITH_SPEC with a symbolic value."""
        sym_val, _ = SymbolicString.symbolic("test")
        state = VMState().push(sym_val).push("")
        instr = _get_instr("f'{1:d}'", "FORMAT_WITH_SPEC")
        result = handle_format_with_spec(instr, state, OpcodeDispatcher())
        assert isinstance(result.new_states[0].stack[0], SymbolicString)

    def test_valid_formatting(self) -> None:
        """Test FORMAT_WITH_SPEC with valid integer and spec."""
        state = VMState().push(42).push("d")
        instr = _get_instr("f'{1:d}'", "FORMAT_WITH_SPEC")
        result = handle_format_with_spec(instr, state, OpcodeDispatcher())
        assert result.new_states[0].stack[0] == "42"

    def test_invalid_formatting(self) -> None:
        """Test FORMAT_WITH_SPEC with invalid format type."""
        state = VMState().push("string").push("d")
        instr = _get_instr("f'{1:d}'", "FORMAT_WITH_SPEC")
        result = handle_format_with_spec(instr, state, OpcodeDispatcher())
        assert isinstance(result.new_states[0].stack[0], SymbolicString)

    def test_unsupported_value(self) -> None:
        """Test FORMAT_WITH_SPEC with an unsupported type."""
        state = VMState().push(SymbolicValue.from_const(object())).push("")
        instr = _get_instr("f'{1:d}'", "FORMAT_WITH_SPEC")
        result = handle_format_with_spec(instr, state, OpcodeDispatcher())
        assert isinstance(result.new_states[0].stack[0], SymbolicString)


class TestConvertValue:
    def test_underflow(self) -> None:
        """Test CONVERT_VALUE underflow behavior."""
        state = VMState()
        instr = _get_instr("f'{1!s}'", "CONVERT_VALUE")
        with pytest.raises(RuntimeError, match="Stack underflow"):
            handle_convert_value(instr, state, OpcodeDispatcher())

    def test_symbolic_value(self) -> None:
        """Test CONVERT_VALUE with a symbolic value."""
        sym_val, _ = SymbolicString.symbolic("test")
        state = VMState().push(sym_val).push(0)
        instr = _get_instr("f'{1!s}'", "CONVERT_VALUE")
        result = handle_convert_value(instr, state, OpcodeDispatcher())
        assert isinstance(result.new_states[0].stack[0], SymbolicString)

    def test_string_conversion(self) -> None:
        """Test CONVERT_VALUE string conversion (!s)."""
        state = VMState().push("test").push(0)
        instr = _get_instr("f'{1!s}'", "CONVERT_VALUE")
        result = handle_convert_value(instr, state, OpcodeDispatcher())
        assert result.new_states[0].stack[0] == "test"

    def test_repr_conversion(self) -> None:
        """Test CONVERT_VALUE repr conversion (!r)."""
        state = VMState().push("test").push(1)
        instr = _get_instr("f'{1!r}'", "CONVERT_VALUE")
        result = handle_convert_value(instr, state, OpcodeDispatcher())
        assert result.new_states[0].stack[0] == "'test'"

    def test_ascii_conversion(self) -> None:
        """Test CONVERT_VALUE ascii conversion (!a)."""
        state = VMState().push("test").push(2)
        instr = _get_instr("f'{1!a}'", "CONVERT_VALUE")
        result = handle_convert_value(instr, state, OpcodeDispatcher())
        assert result.new_states[0].stack[0] == "'test'"

    def test_unknown_conversion(self) -> None:
        """Test CONVERT_VALUE with unknown conversion specifier."""
        state = VMState().push("test").push(3)
        instr = _get_instr("f'{1!s}'", "CONVERT_VALUE")
        result = handle_convert_value(instr, state, OpcodeDispatcher())
        assert isinstance(result.new_states[0].stack[0], SymbolicString)

    def test_unsupported_value(self) -> None:
        """Test CONVERT_VALUE with an unsupported conversion target."""
        state = VMState().push("test").push("not int")
        instr = _get_instr("f'{1!s}'", "CONVERT_VALUE")
        result = handle_convert_value(instr, state, OpcodeDispatcher())
        assert isinstance(result.new_states[0].stack[0], SymbolicString)
