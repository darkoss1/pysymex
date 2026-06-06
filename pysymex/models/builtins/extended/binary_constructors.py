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

"""Binary and object constructor builtin models."""

from __future__ import annotations

import ast
import dataclasses
from typing import TYPE_CHECKING

import z3

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.containers.bytes.shared import symbolic_bytes_literal
from ..base import FunctionModel, ModelResult
from .helpers import (
    constructor_len_expr as _constructor_len_expr,
    resolve_heap_object as _resolve_heap_object,
    type_error_side_effect as _type_error_side_effect,
)
from ..core.iterator_items import (
    concrete_iterable_items,
    contains_definitely_unhashable_item,
    iterator_exhaustion_side_effect,
)
from ..core.helpers import value_error_side_effect as _value_error_side_effect


def _invalid_binary_constructor_call(args: list[StackValue], kwargs: dict[str, StackValue]) -> bool:
    return (
        len(args) > 3
        or bool(set(kwargs) - {"source", "encoding", "errors"})
        or (bool(args) and "source" in kwargs)
        or (len(args) > 1 and "encoding" in kwargs)
        or (len(args) > 2 and "errors" in kwargs)
        or (not args and "source" not in kwargs and bool({"encoding", "errors"} & set(kwargs)))
    )


class BytesModel(FunctionModel):
    """Model for bytes() constructor."""

    name = "bytes"
    qualname = "builtins.bytes"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"bytes_{state.pc}")
        if _invalid_binary_constructor_call(args, kwargs):
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=_type_error_side_effect(
                    "builtins.bytes", "bytes() received invalid arguments"
                ),
            )
        constraints: list[z3.BoolRef] = [constraint]
        if not args and "source" not in kwargs:
            return ModelResult(value=symbolic_bytes_literal(b""))
        else:
            source = args[0] if args else kwargs["source"]
            has_encoding = len(args) > 1 or "encoding" in kwargs
            has_errors = len(args) > 2 or "errors" in kwargs
            if has_errors and not has_encoding:
                return ModelResult(
                    value=result,
                    constraints=constraints,
                    side_effects=_type_error_side_effect(
                        "builtins.bytes", "bytes() errors requires an encoding"
                    ),
                )
            if (
                has_encoding
                and source is not None
                and not isinstance(source, (str, SymbolicString))
            ):
                return ModelResult(
                    value=result,
                    constraints=constraints,
                    side_effects=_type_error_side_effect(
                        "builtins.bytes", "bytes() encoding requires a string source"
                    ),
                )
            if not has_encoding and isinstance(source, (str, SymbolicString)):
                return ModelResult(
                    value=result,
                    constraints=constraints,
                    side_effects=_type_error_side_effect(
                        "builtins.bytes", "bytes() string argument requires an encoding"
                    ),
                )
            if source is None:
                return ModelResult(
                    value=result,
                    constraints=constraints,
                    side_effects=_type_error_side_effect(
                        "builtins.bytes", "bytes() cannot convert None to bytes"
                    ),
                )
            if isinstance(source, int) and source < 0:
                return ModelResult(
                    value=result,
                    constraints=constraints,
                    side_effects=_value_error_side_effect("builtins.bytes", "negative count"),
                )
            if has_encoding:
                encoding_arg = _constructor_arg(args, kwargs, 1, "encoding")
                errors_arg = _constructor_arg(args, kwargs, 2, "errors", "strict")
                if _definitely_invalid_text_argument(
                    encoding_arg
                ) or _definitely_invalid_text_argument(errors_arg):
                    return ModelResult(
                        value=result,
                        constraints=constraints,
                        side_effects=_type_error_side_effect(
                            "builtins.bytes", "bytes() encoding and errors must be strings"
                        ),
                    )
                encoded = _exact_encoded_byte_values(
                    source,
                    encoding_arg,
                    errors_arg,
                )
                if encoded is not None:
                    return ModelResult(value=symbolic_bytes_literal(bytes(encoded)))
            if not has_encoding:
                exact_items = _exact_byte_values(source, state)
                if exact_items is not None:
                    return ModelResult(
                        value=symbolic_bytes_literal(bytes(exact_items)),
                        side_effects=iterator_exhaustion_side_effect(
                            _resolve_heap_object(source, state),
                            state,
                        )
                        or {},
                    )
            val = _constructor_len_expr(_resolve_heap_object(source, state))
            if val is not None:
                constraints.append(result.z3_len == val)
                constraints.append(val >= 0)
        return ModelResult(value=result, constraints=constraints)


class BytearrayModel(FunctionModel):
    """Model for bytearray() constructor."""

    name = "bytearray"
    qualname = "builtins.bytearray"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"bytearray_{state.pc}")
        if _invalid_binary_constructor_call(args, kwargs):
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=_type_error_side_effect(
                    "builtins.bytearray", "bytearray() received invalid arguments"
                ),
            )
        constraints: list[z3.BoolRef] = [constraint]
        if not args and "source" not in kwargs:
            return ModelResult(value=_bytearray_literal([]))
        else:
            source = args[0] if args else kwargs["source"]
            has_encoding = len(args) > 1 or "encoding" in kwargs
            has_errors = len(args) > 2 or "errors" in kwargs
            if has_errors and not has_encoding:
                return ModelResult(
                    value=result,
                    constraints=constraints,
                    side_effects=_type_error_side_effect(
                        "builtins.bytearray", "bytearray() errors requires an encoding"
                    ),
                )
            if (
                has_encoding
                and source is not None
                and not isinstance(source, (str, SymbolicString))
            ):
                return ModelResult(
                    value=result,
                    constraints=constraints,
                    side_effects=_type_error_side_effect(
                        "builtins.bytearray", "bytearray() encoding requires a string source"
                    ),
                )
            if not has_encoding and isinstance(source, (str, SymbolicString)):
                return ModelResult(
                    value=result,
                    constraints=constraints,
                    side_effects=_type_error_side_effect(
                        "builtins.bytearray", "bytearray() string argument requires an encoding"
                    ),
                )
            if source is None:
                return ModelResult(
                    value=result,
                    constraints=constraints,
                    side_effects=_type_error_side_effect(
                        "builtins.bytearray", "bytearray() cannot convert None"
                    ),
                )
            if isinstance(source, int) and source < 0:
                return ModelResult(
                    value=result,
                    constraints=constraints,
                    side_effects=_value_error_side_effect("builtins.bytearray", "negative count"),
                )
            if has_encoding:
                encoding_arg = _constructor_arg(args, kwargs, 1, "encoding")
                errors_arg = _constructor_arg(args, kwargs, 2, "errors", "strict")
                if _definitely_invalid_text_argument(
                    encoding_arg
                ) or _definitely_invalid_text_argument(errors_arg):
                    return ModelResult(
                        value=result,
                        constraints=constraints,
                        side_effects=_type_error_side_effect(
                            "builtins.bytearray",
                            "bytearray() encoding and errors must be strings",
                        ),
                    )
                encoded = _exact_encoded_byte_values(
                    source,
                    encoding_arg,
                    errors_arg,
                )
                if encoded is not None:
                    return ModelResult(value=_bytearray_literal(encoded))
            if not has_encoding:
                exact_items = _exact_byte_values(source, state)
                if exact_items is not None:
                    return ModelResult(
                        value=_bytearray_literal(exact_items),
                        side_effects=iterator_exhaustion_side_effect(
                            _resolve_heap_object(source, state),
                            state,
                        )
                        or {},
                    )
            val = _constructor_len_expr(_resolve_heap_object(source, state))
            if val is not None:
                constraints.append(result.z3_len == val)
                constraints.append(val >= 0)
        return ModelResult(value=result, constraints=constraints)


def _bytearray_literal(values: list[int]) -> SymbolicList:
    return dataclasses.replace(SymbolicList.from_const(values), _type="bytearray")


def _constructor_arg(
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    index: int,
    name: str,
    default: StackValue | None = None,
) -> StackValue | None:
    if len(args) > index:
        return args[index]
    return kwargs.get(name, default)


def _exact_encoded_byte_values(
    source: StackValue,
    encoding: StackValue | None,
    errors: StackValue | None,
) -> list[int] | None:
    text = _exact_text_value(source)
    encoding_text = _exact_text_value(encoding)
    errors_text = _exact_text_value(errors)
    if text is None or encoding_text is None or errors_text is None:
        return None
    try:
        return list(text.encode(encoding_text, errors_text))
    except (LookupError, TypeError, ValueError):
        return None


def _definitely_invalid_text_argument(value: StackValue | None) -> bool:
    if value is None:
        return True
    if isinstance(value, (str, SymbolicString)):
        return False
    if isinstance(value, SymbolicValue):
        concrete = value.value
        return concrete is not None and not isinstance(concrete, str)
    return True


def _exact_text_value(value: StackValue | None) -> str | None:
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
            return _decode_z3_string_escapes(value.z3_str.as_string())
        except z3.Z3Exception:
            return None
    if isinstance(value, SymbolicValue) and isinstance(value.value, str):
        return value.value
    return None


def _decode_z3_string_escapes(value: str) -> str:
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


def _exact_byte_values(source: StackValue, state: VMState) -> list[int] | None:
    raw_source: object = source.value if isinstance(source, SymbolicValue) else source
    if isinstance(raw_source, int):
        if raw_source < 0:
            return None
        return [0] * raw_source
    items = concrete_iterable_items(source, state)
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


class FrozensetModel(FunctionModel):
    """Model for frozenset() constructor."""

    name = "frozenset"
    qualname = "builtins.frozenset"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"frozenset_{state.pc}")
        if len(args) > 1 or kwargs:
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=_type_error_side_effect(
                    "builtins.frozenset", "frozenset() accepts at most one argument"
                ),
            )
        setattr(result, "_type", "frozenset")
        constraints: list[z3.BoolRef] = [constraint]
        if not args:
            return ModelResult(value=_exact_frozenset_value(frozenset()))
        source = _resolve_heap_object(args[0], state)
        if source is None or isinstance(source, (int, float, bool)):
            return ModelResult(
                value=result,
                constraints=constraints,
                side_effects=_type_error_side_effect(
                    "builtins.frozenset", "frozenset() argument is not iterable"
                ),
            )
        direct_items = concrete_iterable_items(source, state)
        if direct_items is not None:
            iterator_side_effects = iterator_exhaustion_side_effect(source, state)
            if contains_definitely_unhashable_item(direct_items, state):
                return ModelResult(
                    value=result,
                    constraints=constraints,
                    side_effects=_type_error_side_effect(
                        "builtins.frozenset",
                        "frozenset() argument contains an unhashable item",
                    ),
                )
            try:
                return ModelResult(
                    value=_exact_frozenset_value(frozenset(direct_items)),
                    side_effects=iterator_side_effects or {},
                )
            except TypeError:
                return ModelResult(
                    value=result,
                    constraints=constraints,
                    side_effects=_type_error_side_effect(
                        "builtins.frozenset",
                        "frozenset() argument contains an unhashable item",
                    ),
                )
        return ModelResult(value=result, constraints=constraints)


class MemoryviewModel(FunctionModel):
    """Model for memoryview()."""

    name = "memoryview"
    qualname = "builtins.memoryview"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"memoryview_{state.pc}")
        if len(args) != 1 or kwargs:
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=_type_error_side_effect(
                    "builtins.memoryview",
                    f"memoryview() received invalid positional argument count: {len(args)}",
                ),
            )
        if args[0] is None or isinstance(args[0], (int, float, bool, str, SymbolicString)):
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=_type_error_side_effect(
                    "builtins.memoryview", "memoryview() requires a bytes-like object"
                ),
            )
        return ModelResult(value=result, constraints=[constraint])


def _exact_frozenset_value(values: frozenset[object]) -> SymbolicList:
    result = SymbolicList.from_const(list(values))
    setattr(result, "_type", "frozenset")
    return result


class ObjectModel(FunctionModel):
    """Model for object()."""

    name = "object"
    qualname = "builtins.object"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"object_{state.pc}")
        if args or kwargs:
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=_type_error_side_effect(
                    "builtins.object", "object() takes no arguments"
                ),
            )
        return ModelResult(value=result, constraints=[constraint])
