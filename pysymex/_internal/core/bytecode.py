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

"""CPython bytecode helpers shared by execution and analysis."""

from __future__ import annotations

import dis
from collections import OrderedDict

from pysymex._internal.core.cache.control import (
    is_process_cache_disabled,
    register_process_cache_clearer,
)

_INSTRUCTION_STREAM_KEY_CACHE_MAX_SIZE = 4096
_INSTRUCTION_STREAM_KEY_CACHE: OrderedDict[
    int,
    tuple[list[dis.Instruction], int, tuple[int, ...]],
] = OrderedDict()

BINARY_OP_SYMBOL_BY_ARG: dict[int, str] = {
    0: "+",
    1: "&",
    2: "//",
    3: "<<",
    4: "@",
    5: "*",
    6: "%",
    7: "|",
    8: "**",
    9: ">>",
    10: "-",
    11: "/",
    12: "^",
    13: "+=",
    14: "&=",
    15: "//=",
    16: "<<=",
    17: "@=",
    18: "*=",
    19: "%=",
    20: "|=",
    21: "**=",
    22: ">>=",
    23: "-=",
    24: "/=",
    25: "^=",
}

COMPARE_OP_SYMBOL_BY_ARG: dict[int, str] = dict(enumerate(dis.cmp_op))

# Direct call instructions encode a positional argument count compatible with
# shared call-target recovery. CALL_FUNCTION_EX instead encodes unpack flags.
DIRECT_CALL_OPCODES = frozenset(("CALL", "CALL_FUNCTION", "CALL_KW", "CALL_METHOD"))
UNPACKED_CALL_OPCODES = frozenset(("CALL_FUNCTION_EX",))
CALL_OPCODES = DIRECT_CALL_OPCODES | UNPACKED_CALL_OPCODES
ATTRIBUTE_OPCODES = frozenset(
    ("DELETE_ATTR", "LOAD_ATTR", "LOAD_METHOD", "LOAD_SUPER_ATTR", "STORE_ATTR"),
)
SUBSCRIPT_OPCODES = frozenset(("BINARY_SUBSCR", "DELETE_SUBSCR", "STORE_SUBSCR"))


def _canonicalize_compare_op_text(value: object) -> str:
    """Return a plain comparison symbol from CPython/dis metadata text.

    Python 3.13 can expose ``COMPARE_OP`` values as strings such as
    ``"bool(!=)"`` when the interpreter emits the bool-forcing compare form.
    The symbolic comparison layer needs the semantic operator, not the display
    wrapper.
    """
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if text.startswith("bool(") and text.endswith(")"):
        return text[5:-1].strip()
    return text


def get_starts_line(instr: dis.Instruction) -> int | None:
    """Return the instruction starting line, when CPython exposes it as an integer."""
    starts_line: object = getattr(instr, "starts_line", None)
    if (
        starts_line is not None
        and isinstance(starts_line, int)
        and not isinstance(starts_line, bool)
    ):
        return starts_line
    return None


def get_position_line(instr: dis.Instruction) -> int | None:
    """Return the instruction position line, excluding boolean CPython sentinels."""
    positions = getattr(instr, "positions", None)
    line: object = getattr(positions, "lineno", None) if positions is not None else None
    if line is not None and isinstance(line, int) and not isinstance(line, bool):
        return line
    return None


def get_position_column(instr: dis.Instruction) -> int | None:
    """Return the instruction position column, excluding boolean CPython sentinels."""
    positions = getattr(instr, "positions", None)
    column: object = getattr(positions, "col_offset", None) if positions is not None else None
    if column is not None and isinstance(column, int) and not isinstance(column, bool):
        return column
    return None


def instruction_stream_key(instructions: list[dis.Instruction]) -> tuple[int, ...]:
    """Return a stable process-local identity key for an instruction stream.

    Instruction lists are copied when execution enters or resumes nested frames,
    but the cached ``dis.Instruction`` objects remain shared. Keying by the
    instruction object identities keeps per-stream metadata stable across those
    list copies without conflating distinct code objects that reuse bytecode
    offsets. Execution-owned instruction lists are treated as immutable streams;
    repeated calls for the same list object reuse the computed key.
    """
    if is_process_cache_disabled():
        return tuple(id(instr) for instr in instructions)

    cache_key = id(instructions)
    cached = _INSTRUCTION_STREAM_KEY_CACHE.get(cache_key)
    if cached is not None:
        cached_instructions, cached_length, cached_key = cached
        if cached_instructions is instructions and cached_length == len(instructions):
            _INSTRUCTION_STREAM_KEY_CACHE.move_to_end(cache_key)
            return cached_key

    stream_key = tuple(id(instr) for instr in instructions)
    _INSTRUCTION_STREAM_KEY_CACHE[cache_key] = (instructions, len(instructions), stream_key)
    if len(_INSTRUCTION_STREAM_KEY_CACHE) > _INSTRUCTION_STREAM_KEY_CACHE_MAX_SIZE:
        _INSTRUCTION_STREAM_KEY_CACHE.popitem(last=False)
    return stream_key


def clear_instruction_stream_key_cache() -> None:
    """Clear cached instruction-stream identity keys."""
    _INSTRUCTION_STREAM_KEY_CACHE.clear()


register_process_cache_clearer(
    "core.instruction_stream_key_cache",
    clear_instruction_stream_key_cache,
)


def global_name_from_argval(argval: object) -> str:
    """Return the global name encoded in a ``LOAD_GLOBAL`` instruction operand."""
    return str(argval)


def bytecode_uses_end_for_cleanup() -> bool:
    """Return whether the running interpreter emits ``END_FOR`` loop cleanup."""
    return "END_FOR" in dis.opmap


def resolve_binary_op_symbol(instr: dis.Instruction) -> str:
    """Return the best available ``BINARY_OP`` symbol, or ``""`` if unknown."""
    argrepr = getattr(instr, "argrepr", "")
    if argrepr:
        return str(argrepr).strip()
    argval = getattr(instr, "argval", None)
    if isinstance(argval, str):
        return argval.strip()
    arg = getattr(instr, "arg", None)
    if isinstance(arg, int):
        return BINARY_OP_SYMBOL_BY_ARG.get(arg, "")
    if isinstance(argval, int):
        return BINARY_OP_SYMBOL_BY_ARG.get(argval, "")
    return ""


def resolve_compare_op_symbol(instr: dis.Instruction) -> str:
    """Return the best available ``COMPARE_OP`` symbol, or ``""`` if unknown."""
    argval = getattr(instr, "argval", None)
    normalized = _canonicalize_compare_op_text(argval)
    if normalized:
        return normalized
    argrepr = getattr(instr, "argrepr", "")
    normalized = _canonicalize_compare_op_text(str(argrepr) if argrepr else "")
    if normalized:
        return normalized
    if isinstance(argval, int):
        return COMPARE_OP_SYMBOL_BY_ARG.get(argval, "")
    arg = getattr(instr, "arg", None)
    if isinstance(arg, int):
        return COMPARE_OP_SYMBOL_BY_ARG.get(arg, "")
    return ""
