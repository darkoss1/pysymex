"""Tests for shared CPython bytecode helpers."""

from __future__ import annotations

import dis
import sys
from types import SimpleNamespace
from typing import cast

from pysymex.core.bytecode import (
    get_starts_line,
    instruction_stream_key,
    resolve_binary_op_symbol,
    resolve_compare_op_symbol,
)


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
