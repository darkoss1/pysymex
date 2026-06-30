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

"""Shared exact byte-conversion helpers for binary constructor models."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING, Literal

import z3

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.iteration.sources import IterationSources


def invalid_binary_constructor_call(
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> bool:
    """Return whether a bytes-like constructor call has impossible binding."""
    return (
        len(args) > 3
        or bool(set(kwargs) - {"source", "encoding", "errors"})
        or (bool(args) and "source" in kwargs)
        or (len(args) > 1 and "encoding" in kwargs)
        or (len(args) > 2 and "errors" in kwargs)
        or (not args and "source" not in kwargs and bool({"encoding", "errors"} & set(kwargs)))
    )


def constructor_arg(
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    index: int,
    name: str,
    default: StackValue | None = None,
) -> StackValue | None:
    if len(args) > index:
        return args[index]
    return kwargs.get(name, default)


def exact_encoded_byte_values(
    source: StackValue,
    encoding: StackValue | None,
    errors: StackValue | None,
) -> list[int] | None:
    text = exact_text_value(source)
    encoding_text = exact_text_value(encoding)
    errors_text = exact_text_value(errors)
    if text is None or encoding_text is None or errors_text is None:
        return None
    try:
        return list(text.encode(encoding_text, errors_text))
    except (LookupError, TypeError, ValueError):
        return None


def definitely_invalid_text_argument(value: StackValue | None) -> bool:
    if value is None:
        return True
    if isinstance(value, (str, SymbolicString)):
        return False
    if isinstance(value, SymbolicValue):
        concrete = value.value
        return concrete is not None and not isinstance(concrete, str)
    return True


def exact_text_value(value: StackValue | None) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, SymbolicString) and z3.is_string_value(value.z3_str):
        literal_name = getattr(value, "name", "")
        try:
            literal_value = ast.literal_eval(literal_name)
        except (SyntaxError, ValueError):
            literal_value = None
        if isinstance(literal_value, str):
            return literal_value
        try:
            return decode_z3_string_escapes(value.z3_str.as_string())
        except z3.Z3Exception:
            return None
    if isinstance(value, SymbolicValue) and isinstance(value.value, str):
        return value.value
    return None


def decode_z3_string_escapes(value: str) -> str:
    parts: list[str] = []
    index = 0
    while index < len(value):
        if value.startswith("\\u{", index):
            end = value.find("}", index + 3)
            if end != -1:
                try:
                    parts.append(chr(int(value[index + 3 : end], 16)))
                except ValueError:
                    parts.append(value[index])
                    index += 1
                    continue
                index = end + 1
                continue
        parts.append(value[index])
        index += 1
    return "".join(parts)


def exact_byte_values(source: StackValue, state: VMState) -> list[int] | None:
    raw_source: object = source.value if isinstance(source, SymbolicValue) else source
    if isinstance(raw_source, int):
        return None
    items = IterationSources.iterable_items(source, state)
    if items is None:
        return None
    values: list[int] = []
    for item in items:
        if isinstance(item, SymbolicValue):
            item = item.value
        if isinstance(item, bool):
            values.append(int(item))
        elif isinstance(item, int) and 0 <= item <= 255:
            values.append(item)
        else:
            return None
    return values


def exact_byte_items(source: StackValue, state: VMState) -> list[StackValue] | None:
    """Return retained finite byte items, allowing proved byte-valued symbolic ints."""
    raw_source: object = source.value if isinstance(source, SymbolicValue) else source
    if isinstance(raw_source, int):
        return None
    items = IterationSources.iterable_items(source, state)
    if items is None:
        return None
    values: list[StackValue] = []
    for item in items:
        retained = _retained_byte_item(item, state)
        if retained is None:
            return None
        values.append(retained)
    return values


def _retained_byte_item(item: StackValue, state: VMState) -> StackValue | None:
    if isinstance(item, SymbolicValue):
        concrete = item.value
        if concrete is not None:
            return _concrete_byte_item(concrete)
        if _symbolic_value_is_byte(item, state):
            return item
        return None
    return _concrete_byte_item(item)


def _concrete_byte_item(item: object) -> StackValue | None:
    if isinstance(item, bool):
        return int(item)
    if isinstance(item, int) and 0 <= item <= 255:
        return item
    return None


def _symbolic_value_is_byte(item: SymbolicValue, state: VMState) -> bool:
    _ = state
    if not z3.is_true(simplify_expr(z3.Or(item.is_int, item.is_bool))):
        return False
    min_value = item.min_val
    max_value = item.max_val
    return (
        isinstance(min_value, int)
        and isinstance(max_value, int)
        and 0 <= min_value
        and max_value <= 255
    )


def exact_byte_count(source: StackValue) -> int | None:
    """Return the exact zero-fill count accepted by bytes-like constructors."""
    if isinstance(source, int):
        return source
    if isinstance(source, SymbolicValue) and isinstance(source.value, int):
        return source.value
    return None


def exact_byte_values_error(source: StackValue, state: VMState) -> Literal["type", "value"] | None:
    """Classify definite invalid items in an exact bytes-constructor iterable."""
    items = IterationSources.iterable_items(source, state)
    if items is None:
        return None
    for item in items:
        if isinstance(item, SymbolicValue):
            concrete = item.value
            if concrete is None:
                continue
            item = concrete
        if isinstance(item, bool):
            continue
        if isinstance(item, int):
            if not 0 <= item <= 255:
                return "value"
            continue
        if item is None or type(item) in (float, str, bytes, bytearray, list, tuple, dict, set):
            return "type"
    return None
