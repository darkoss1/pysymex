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

"""Exact helpers for string translation models."""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeAlias, cast

from pysymex.core.constants import Z3_TRUE
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.models.builtins.core.helpers import resolve_heap_object

from .shared import (
    ModelResult,
    SymbolicString,
    SymbolicValue,
    concrete_string_literal,
    method_type_error_result,
)

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.typing import StackValue

_UNKNOWN = object()
_TranslateValue: TypeAlias = str | int | None
_TranslateTable: TypeAlias = dict[int | str, _TranslateValue]


def exact_maketrans_result(args: list[StackValue], state: VMState) -> ModelResult | None:
    values: list[str | _TranslateTable] = []
    for arg in args:
        value = _concrete_maketrans_argument(arg, state)
        if value is _UNKNOWN:
            return None
        if not isinstance(value, (str, dict)):
            return method_type_error_result("str.maketrans", state)
        values.append(cast("_TranslateTable", value) if isinstance(value, dict) else value)
    try:
        table = _call_str_maketrans(values)
    except TypeError:
        return method_type_error_result("str.maketrans", state)
    except ValueError as exc:
        return _value_error_dict_result("maketrans", str(exc), state)
    if table is None:
        return None
    return ModelResult(value=SymbolicDict.from_const(cast("dict[object, object]", table)))


def exact_translate_result(
    source_arg: StackValue,
    table_arg: StackValue,
    state: VMState,
) -> ModelResult | None:
    source = concrete_string_literal(source_arg)
    table = _concrete_mapping(table_arg, state)
    if source is None or table is None:
        return None
    try:
        return ModelResult(value=SymbolicString.from_const(source.translate(table)))
    except TypeError:
        return method_type_error_result("str.translate", state)
    except ValueError as exc:
        return _value_error_string_result("translate", str(exc), state)


def _call_str_maketrans(values: list[str | _TranslateTable]) -> dict[int, int | str | None] | None:
    if len(values) == 1:
        if not isinstance(values[0], dict):
            return None
        return str.maketrans(values[0])
    if len(values) == 2:
        return cast(
            "dict[int, int | str | None]",
            str.maketrans(cast("str", values[0]), cast("str", values[1])),
        )
    if len(values) == 3:
        return cast(
            "dict[int, int | str | None]",
            str.maketrans(
                cast("str", values[0]),
                cast("str", values[1]),
                cast("str", values[2]),
            ),
        )
    return None


def _concrete_maketrans_argument(value: object, state: VMState) -> object:
    mapping = _concrete_mapping(value, state)
    if mapping is not None:
        return mapping
    text = concrete_string_literal(value)
    if text is not None:
        return text
    return _concrete_python_value(value, state)


def _concrete_mapping(value: object, state: VMState) -> _TranslateTable | None:
    resolved = resolve_heap_object(cast("StackValue", value), state)
    if isinstance(resolved, SymbolicDict):
        concrete_items = resolved.concrete_items
    elif isinstance(resolved, dict):
        concrete_items = dict(cast("dict[object, object]", resolved))
    else:
        return None
    if concrete_items is None:
        return None
    normalized: _TranslateTable = {}
    for key, item in concrete_items.items():
        concrete_key = _concrete_python_value(key, state)
        concrete_value = _concrete_python_value(item, state)
        if concrete_key is _UNKNOWN or concrete_value is _UNKNOWN:
            return None
        if not isinstance(concrete_key, (int, str)):
            return None
        if concrete_value is not None and not isinstance(concrete_value, (int, str)):
            return None
        normalized[concrete_key] = concrete_value
    return normalized


def _concrete_python_value(value: object, state: VMState) -> object:
    resolved = resolve_heap_object(cast("StackValue", value), state)
    text = concrete_string_literal(resolved)
    if text is not None:
        return text
    if isinstance(resolved, SymbolicValue):
        if resolved.value is not None:
            return resolved.value
        return _UNKNOWN
    if isinstance(resolved, SymbolicNone):
        return None
    if isinstance(resolved, bool):
        return int(resolved)
    if isinstance(resolved, int):
        return resolved
    if resolved is None:
        return None
    return _UNKNOWN


def _value_error_dict_result(name: str, message: str, state: VMState) -> ModelResult:
    result, constraint = SymbolicDict.symbolic(f"{name}_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects={
            "potential_exception": {
                "type": "ValueError",
                "condition": Z3_TRUE,
                "message": message,
            }
        },
    )


def _value_error_string_result(name: str, message: str, state: VMState) -> ModelResult:
    result, constraint = SymbolicString.symbolic(f"{name}_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects={
            "potential_exception": {
                "type": "ValueError",
                "condition": Z3_TRUE,
                "message": message,
            }
        },
    )
