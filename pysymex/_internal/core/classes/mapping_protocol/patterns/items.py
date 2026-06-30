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

"""Literal and conditional ``__getitem__`` mapping extraction."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, cast

from pysymex._internal.core.classes.mapping_protocol.patterns.constants import (
    NO_CONSTANT_RETURN,
    constant_return_value,
)
from pysymex._internal.core.classes.mapping_protocol.patterns.instructions import (
    effective_instructions,
    loads_local,
)

if TYPE_CHECKING:
    import dis
    import types

_CONDITIONAL_FALSE_JUMPS = frozenset(
    ("POP_JUMP_BACKWARD_IF_FALSE", "POP_JUMP_FORWARD_IF_FALSE", "POP_JUMP_IF_FALSE"),
)
_NO_CASE_KEY: Final = object()


def static_item_mapping(
    keys_code: types.CodeType | None,
    getitem_code: types.CodeType | None,
) -> dict[object, object] | None:
    """Extract a static mapping from literal keys and simple ``__getitem__`` bodies."""
    keys = _literal_keys_return_value(keys_code)
    if keys is None:
        return None

    literal_items = _literal_dict_getitem_mapping(getitem_code)
    if literal_items is not None:
        return _literal_items_for_keys(keys, literal_items)

    conditional_items = _conditional_getitem_mapping(getitem_code)
    if conditional_items is not None:
        return _literal_items_for_keys(keys, conditional_items)

    item_constant = constant_return_value(getitem_code)
    if item_constant is NO_CONSTANT_RETURN:
        return None
    return dict.fromkeys(keys, item_constant)


def _literal_keys_return_value(code: types.CodeType | None) -> tuple[object, ...] | None:
    """Return keys from literal tuple/list-return method bodies."""
    constant = constant_return_value(code)
    if isinstance(constant, tuple):
        return cast("tuple[object, ...]", constant)

    instructions = effective_instructions(code)
    if code is None or not instructions or instructions[-1].opname != "RETURN_VALUE":
        return None
    body = instructions[:-1]
    if len(body) == 1 and body[0].opname == "BUILD_LIST" and body[0].arg == 0:
        return ()
    if len(body) >= 1 and body[-1].opname == "BUILD_LIST" and body[-1].arg == len(body) - 1:
        values = [instr.argval for instr in body[:-1] if instr.opname == "LOAD_CONST"]
        return tuple(values) if len(values) == len(body) - 1 else None
    if (
        len(body) == 3
        and body[0].opname == "BUILD_LIST"
        and body[0].arg == 0
        and body[1].opname == "LOAD_CONST"
        and body[2].opname == "LIST_EXTEND"
    ):
        extended_values: object = body[1].argval
        if isinstance(extended_values, tuple):
            return cast("tuple[object, ...]", extended_values)
    return None


def _literal_dict_getitem_mapping(code: types.CodeType | None) -> dict[object, object] | None:
    """Return a literal dict from ``return {<const>: <const>}[key]`` bodies."""
    instructions = effective_instructions(code)
    if code is None or len(instructions) < 4 or instructions[-1].opname != "RETURN_VALUE":
        return None
    if not loads_local(instructions[-3], code, 1) or instructions[-2].opname != "BINARY_SUBSCR":
        return None
    return _literal_dict_from_instructions(instructions[:-3])


def _conditional_getitem_mapping(code: types.CodeType | None) -> dict[object, object] | None:
    """Return cases from ``if key == <const>: return <const>`` chains."""
    instructions = effective_instructions(code)
    if code is None:
        return None
    cases: dict[object, object] = {}
    index = 0
    while index < len(instructions):
        matched = _match_conditional_return_case(instructions, code, index)
        if matched is None:
            break
        next_index, key, value = matched
        if key in cases:
            return None
        cases[key] = value
        index = next_index
    return cases or None


def _match_conditional_return_case(
    instructions: list[dis.Instruction],
    code: types.CodeType,
    index: int,
) -> tuple[int, object, object] | None:
    """Match one linear equality branch and return ``(next_index, key, value)``."""
    if index + 4 >= len(instructions):
        return None

    key = _comparison_case_key(instructions[index], instructions[index + 1], code)
    compare = instructions[index + 2]
    jump = instructions[index + 3]
    if key is _NO_CASE_KEY:
        return None
    if compare.opname != "COMPARE_OP" or compare.argval != "==":
        return None
    if jump.opname not in _CONDITIONAL_FALSE_JUMPS:
        return None

    returned = _constant_return_at(instructions, index + 4)
    if returned is None:
        return None
    next_index, value = returned
    target: object = jump.argval
    if not isinstance(target, int):
        return None
    if next_index >= len(instructions) or instructions[next_index].offset != target:
        return None
    return next_index, key, value


def _comparison_case_key(
    left: dis.Instruction,
    right: dis.Instruction,
    code: types.CodeType,
) -> object:
    """Return the constant key from ``key == <const>`` or ``<const> == key``."""
    if loads_local(left, code, 1) and right.opname == "LOAD_CONST":
        return right.argval
    if left.opname == "LOAD_CONST" and loads_local(right, code, 1):
        return left.argval
    return _NO_CASE_KEY


def _constant_return_at(
    instructions: list[dis.Instruction],
    index: int,
) -> tuple[int, object] | None:
    """Return ``(next_index, constant)`` for a constant return at *index*."""
    if index >= len(instructions):
        return None
    first = instructions[index]
    if first.opname == "RETURN_CONST":
        return index + 1, first.argval
    if (
        index + 1 < len(instructions)
        and first.opname == "LOAD_CONST"
        and instructions[index + 1].opname == "RETURN_VALUE"
    ):
        return index + 2, first.argval
    return None


def _literal_dict_from_instructions(
    instructions: list[dis.Instruction],
) -> dict[object, object] | None:
    """Return the literal dict built by a compact BUILD_* instruction sequence."""
    if not instructions:
        return None
    build = instructions[-1]
    count = build.arg
    if count is None:
        return None
    if build.opname == "BUILD_CONST_KEY_MAP":
        return _build_const_key_map(instructions, count)
    if build.opname == "BUILD_MAP":
        return _build_map(instructions, count)
    return None


def _build_const_key_map(
    instructions: list[dis.Instruction],
    count: int,
) -> dict[object, object] | None:
    """Return a dict for ``LOAD_CONST*; LOAD_CONST keys; BUILD_CONST_KEY_MAP``."""
    if len(instructions) != count + 2:
        return None
    raw_keys: object = instructions[-2].argval
    if not isinstance(raw_keys, tuple):
        return None
    keys = cast("tuple[object, ...]", raw_keys)
    if len(keys) != count:
        return None
    values = [instr.argval for instr in instructions[:count] if instr.opname == "LOAD_CONST"]
    if len(values) != count:
        return None
    return dict(zip(keys, values, strict=True))


def _build_map(
    instructions: list[dis.Instruction],
    count: int,
) -> dict[object, object] | None:
    """Return a dict for ``LOAD_CONST key/value*; BUILD_MAP`` bodies."""
    if len(instructions) != count * 2 + 1:
        return None
    result: dict[object, object] = {}
    pairs = instructions[:-1]
    for index in range(0, len(pairs), 2):
        key_instr = pairs[index]
        value_instr = pairs[index + 1]
        if key_instr.opname != "LOAD_CONST" or value_instr.opname != "LOAD_CONST":
            return None
        result[key_instr.argval] = value_instr.argval
    return result


def _literal_items_for_keys(
    keys: tuple[object, ...],
    literal_items: dict[object, object],
) -> dict[object, object] | None:
    """Return item values for known keys, leaving missing-key paths inconclusive."""
    result: dict[object, object] = {}
    for key in keys:
        if key not in literal_items:
            return None
        result[key] = literal_items[key]
    return result
