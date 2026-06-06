# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Bytecode categories shared by data-flow analyses."""

from __future__ import annotations

import dis
from typing import SupportsIndex, SupportsInt, cast

from pysymex.core.bytecode import (
    get_starts_line,
    resolve_binary_op_symbol,
    resolve_compare_op_symbol,
)

LOAD_OPS = {
    "LOAD_NAME",
    "LOAD_FAST",
    "LOAD_GLOBAL",
    "LOAD_DEREF",
    "LOAD_FAST_CHECK",
    "LOAD_FAST_AND_CLEAR",
    "LOAD_CLOSURE",
}

STORE_OPS = {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}
DELETE_OPS = {"DELETE_NAME", "DELETE_FAST", "DELETE_GLOBAL", "DELETE_DEREF"}
COUNTED_CALL_OPS = {"CALL", "CALL_FUNCTION", "CALL_METHOD", "CALL_KW"}
SPLAT_CALL_OPS = {"CALL_FUNCTION_EX"}

BINARY_OPCODE_OPERATORS = {
    "BINARY_ADD": "+",
    "BINARY_SUBTRACT": "-",
    "BINARY_MULTIPLY": "*",
    "BINARY_TRUE_DIVIDE": "/",
    "BINARY_FLOOR_DIVIDE": "//",
    "BINARY_MODULO": "%",
    "BINARY_POWER": "**",
    "BINARY_LSHIFT": "<<",
    "BINARY_RSHIFT": ">>",
    "BINARY_AND": "&",
    "BINARY_XOR": "^",
    "BINARY_OR": "|",
    "BINARY_MATRIX_MULTIPLY": "@",
    "INPLACE_ADD": "+",
    "INPLACE_SUBTRACT": "-",
    "INPLACE_MULTIPLY": "*",
    "INPLACE_TRUE_DIVIDE": "/",
    "INPLACE_FLOOR_DIVIDE": "//",
    "INPLACE_MODULO": "%",
    "INPLACE_POWER": "**",
    "INPLACE_LSHIFT": "<<",
    "INPLACE_RSHIFT": ">>",
    "INPLACE_AND": "&",
    "INPLACE_XOR": "^",
    "INPLACE_OR": "|",
    "INPLACE_MATRIX_MULTIPLY": "@",
}

UNARY_OPCODE_OPERATORS = {
    "UNARY_POSITIVE": "+",
    "UNARY_NEGATIVE": "-",
    "UNARY_NOT": "not",
    "UNARY_INVERT": "~",
}


def normalize_binary_operator(operator: str) -> str:
    """Normalize in-place binary symbols to their result operator."""
    if operator.endswith("=") and operator not in {"==", "!=", "<=", ">="}:
        return operator[:-1]
    return operator


def binary_operator_for_instruction(instr: dis.Instruction) -> str:
    """Resolve a binary operation symbol from supported Python bytecode."""
    if instr.opname == "BINARY_OP":
        return normalize_binary_operator(resolve_binary_op_symbol(instr))
    return BINARY_OPCODE_OPERATORS.get(instr.opname, "")


def compare_operator_for_instruction(instr: dis.Instruction) -> str:
    """Resolve a comparison operation symbol from supported Python bytecode."""
    if instr.opname == "COMPARE_OP":
        return resolve_compare_op_symbol(instr)
    return ""


def unary_operator_for_instruction(instr: dis.Instruction) -> str:
    """Resolve a unary operation symbol from supported Python bytecode."""
    if instr.opname == "UNARY_OP":
        return str(instr.argrepr or instr.argval or "")
    return UNARY_OPCODE_OPERATORS.get(instr.opname, "")


def get_line_number(instr: dis.Instruction) -> int | None:
    """Return the source line for an instruction."""
    return get_starts_line(instr)


def extend_unknowns(stack: list[object], count: int, unknown: object) -> None:
    """Push ``count`` unknown values onto a symbolic bytecode stack."""
    for _ in range(count):
        stack.append(unknown)


def instruction_int_arg(value: object) -> int:
    """Convert an instruction argument to int using the historical analyzer policy."""
    return int(cast(str | bytes | bytearray | SupportsInt | SupportsIndex, value))


def is_counted_call_instruction(instr: dis.Instruction) -> bool:
    """Return True for call opcodes whose operand is an explicit argument count."""
    return instr.opname in COUNTED_CALL_OPS


def is_splat_call_instruction(instr: dis.Instruction) -> bool:
    """Return True for call opcodes whose operand is flags for *args/**kwargs."""
    return instr.opname in SPLAT_CALL_OPS


def counted_call_arg_count(instr: dis.Instruction) -> int:
    """Return explicit argument count for counted call opcodes."""
    if isinstance(instr.argval, int):
        return instr.argval
    if isinstance(instr.arg, int):
        return instr.arg
    return 0


def counted_call_metadata_count(instr: dis.Instruction) -> int:
    """Return non-argument call metadata entries on the stack."""
    return 1 if instr.opname == "CALL_KW" else 0


def splat_call_has_kwargs(instr: dis.Instruction) -> bool:
    """Return whether CALL_FUNCTION_EX consumes a **kwargs mapping."""
    flags = instr.argval if isinstance(instr.argval, int) else instr.arg
    return bool((flags or 0) & 1)


def splat_call_payload_count(instr: dis.Instruction) -> int:
    """Return *args/**kwargs payload entries consumed before the callable."""
    return 2 if splat_call_has_kwargs(instr) else 1


__all__ = [
    "BINARY_OPCODE_OPERATORS",
    "COUNTED_CALL_OPS",
    "DELETE_OPS",
    "LOAD_OPS",
    "STORE_OPS",
    "SPLAT_CALL_OPS",
    "UNARY_OPCODE_OPERATORS",
    "binary_operator_for_instruction",
    "compare_operator_for_instruction",
    "counted_call_arg_count",
    "counted_call_metadata_count",
    "extend_unknowns",
    "get_line_number",
    "instruction_int_arg",
    "is_counted_call_instruction",
    "is_splat_call_instruction",
    "normalize_binary_operator",
    "splat_call_has_kwargs",
    "splat_call_payload_count",
    "unary_operator_for_instruction",
]
