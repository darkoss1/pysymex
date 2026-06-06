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

"""Call opcode helpers for bytecode pattern recognizers."""

from __future__ import annotations

import dis
from collections.abc import Sequence
from typing import Final

POSITIONAL_CALL_OPS: Final = frozenset({"CALL", "CALL_FUNCTION", "CALL_METHOD"})
KEYWORD_CALL_OPS: Final = frozenset({"CALL_KW", "CALL_FUNCTION_KW"})
COUNTED_CALL_OPS: Final = frozenset({*POSITIONAL_CALL_OPS, *KEYWORD_CALL_OPS})
CALL_OPS: Final = frozenset({*COUNTED_CALL_OPS, "CALL_FUNCTION_EX"})
CALL_PREP_OPS: Final = frozenset({"CACHE", "PRECALL"})


def is_call_instruction(instr: dis.Instruction) -> bool:
    """Return whether an instruction performs a function call."""
    return instr.opname in CALL_OPS


def is_positional_call_instruction(instr: dis.Instruction) -> bool:
    """Return whether a call instruction has only explicit positional arguments."""
    return instr.opname in POSITIONAL_CALL_OPS


def call_arg_count(instr: dis.Instruction) -> int | None:
    """Return explicit argument count for counted call opcodes."""
    if instr.opname not in COUNTED_CALL_OPS:
        return None
    if isinstance(instr.argval, int):
        return instr.argval
    if isinstance(instr.arg, int):
        return instr.arg
    return None


def call_has_keyword_metadata(
    instructions: Sequence[dis.Instruction],
    call_index: int,
) -> bool:
    """Return whether a counted call carries keyword names."""
    instruction = instructions[call_index]
    if instruction.opname in KEYWORD_CALL_OPS:
        return True
    if instruction.opname not in POSITIONAL_CALL_OPS:
        return False
    index = call_index - 1
    while index >= 0:
        previous = instructions[index]
        if previous.opname in CALL_PREP_OPS:
            index -= 1
            continue
        return previous.opname == "KW_NAMES"
    return False


__all__ = [
    "CALL_OPS",
    "KEYWORD_CALL_OPS",
    "COUNTED_CALL_OPS",
    "POSITIONAL_CALL_OPS",
    "call_arg_count",
    "call_has_keyword_metadata",
    "is_call_instruction",
    "is_positional_call_instruction",
]
