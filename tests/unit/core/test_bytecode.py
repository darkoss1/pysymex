"""Tests for shared CPython bytecode helpers."""

from __future__ import annotations

import dis
import sys
from types import SimpleNamespace
from typing import cast

from pysymex._internal.core.bytecode import (
    CALL_OPCODES,
    DIRECT_CALL_OPCODES,
    UNPACKED_CALL_OPCODES,
    get_position_line,
    get_starts_line,
    instruction_stream_key,
    resolve_binary_op_symbol,
    resolve_compare_op_symbol,
)


def test_call_opcode_families_distinguish_argcount_and_unpack_encodings() -> None:
    assert DIRECT_CALL_OPCODES == {"CALL", "CALL_FUNCTION", "CALL_KW", "CALL_METHOD"}
    assert UNPACKED_CALL_OPCODES == {"CALL_FUNCTION_EX"}
    assert CALL_OPCODES == DIRECT_CALL_OPCODES | UNPACKED_CALL_OPCODES


class TestGetStartsLine:
    """Tests for get_starts_line()."""

    def test_returns_int_or_none(self) -> None:
        code = compile("x = 1", "<test>", "exec")
        for instr in dis.get_instructions(code):
            result = get_starts_line(instr)
            assert result is None or isinstance(result, int)

    def test_multiline_code_has_line_info(self) -> None:
        code = compile("x = 1\ny = 2\nz = x + y", "<test>", "exec")
        results = [get_starts_line(instr) for instr in dis.get_instructions(code)]

        if sys.version_info >= (3, 13):
            assert all(result is None for result in results)
        else:
            assert any(isinstance(result, int) for result in results)

    def test_never_returns_bool(self) -> None:
        code = compile("x = 1", "<test>", "exec")
        for instr in dis.get_instructions(code):
            result = get_starts_line(instr)
            if result is not None:
                assert not isinstance(result, bool)


class TestGetPositionLine:
    def test_returns_position_lineno_when_it_is_real_int(self) -> None:
        instruction = cast(
            "dis.Instruction",
            SimpleNamespace(positions=SimpleNamespace(lineno=42)),
        )

        assert get_position_line(instruction) == 42

    def test_never_returns_bool_position_lineno(self) -> None:
        instruction = cast(
            "dis.Instruction",
            SimpleNamespace(positions=SimpleNamespace(lineno=True)),
        )

        assert get_position_line(instruction) is None


class TestInstructionStreamKey:
    def test_reuses_key_for_same_instruction_list(self) -> None:
        code = compile("x = 1\ny = x + 2", "<test>", "exec")
        instructions = list(dis.get_instructions(code))

        first = instruction_stream_key(instructions)
        second = instruction_stream_key(instructions)

        assert second is first

    def test_copied_instruction_list_has_equal_key(self) -> None:
        code = compile("x = 1\ny = x + 2", "<test>", "exec")
        instructions = list(dis.get_instructions(code))

        assert instruction_stream_key(list(instructions)) == instruction_stream_key(instructions)


class TestResolveBinaryOpSymbol:
    def test_resolves_real_cpython_binary_op_arg_when_argrepr_present(self) -> None:
        def target(x: int, y: int) -> int:
            return x + y

        instruction = next(
            instr for instr in dis.get_instructions(target) if instr.opname == "BINARY_OP"
        )

        assert resolve_binary_op_symbol(instruction) == "+"

    def test_resolves_numeric_arg_when_argrepr_is_missing(self) -> None:
        instruction = cast(
            "dis.Instruction",
            SimpleNamespace(opname="BINARY_OP", arg=11, argval=11, argrepr=""),
        )

        assert resolve_binary_op_symbol(instruction) == "/"


class TestResolveCompareOpSymbol:
    def test_resolves_real_cpython_compare_op_arg_when_argval_present(self) -> None:
        def target(x: int, y: int) -> bool:
            return x < y

        instruction = next(
            instr for instr in dis.get_instructions(target) if instr.opname == "COMPARE_OP"
        )

        assert resolve_compare_op_symbol(instruction) == "<"

    def test_resolves_numeric_arg_when_argrepr_is_missing(self) -> None:
        instruction = cast(
            "dis.Instruction",
            SimpleNamespace(opname="COMPARE_OP", arg=4, argval=4, argrepr=""),
        )

        assert resolve_compare_op_symbol(instruction) == ">"

    def test_resolves_python313_bool_compare_display_wrapper(self) -> None:
        instruction = cast(
            "dis.Instruction",
            SimpleNamespace(opname="COMPARE_OP", arg=119, argval="bool(!=)", argrepr="bool(!=)"),
        )

        assert resolve_compare_op_symbol(instruction) == "!="
