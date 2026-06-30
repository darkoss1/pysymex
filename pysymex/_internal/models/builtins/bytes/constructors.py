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

"""Bytes and bytearray constructor builtin models."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.models.contracts.results import SideEffects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.models.builtins.bytes.conversion import (
    constructor_arg,
    definitely_invalid_text_argument,
    exact_byte_count,
    exact_byte_items,
    exact_byte_values,
    exact_byte_values_error,
    exact_encoded_byte_values,
    invalid_binary_constructor_call,
)
from pysymex._internal.models.builtins.common.dynamic import DynamicBuiltinOps
from pysymex._internal.models.builtins.iteration.consumption import iterator_exhaustion_side_effect
from pysymex._internal.models.builtins.types.containers.bytes.shared import (
    symbolic_bytes_items,
    symbolic_bytes_literal,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

# Small mutable buffers retain concrete items for exact mutation modeling.
_EAGER_ZERO_BYTEARRAY_LIMIT = 4096


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
        result = dataclasses.replace(result, _type="bytes")
        if invalid_binary_constructor_call(args, kwargs):
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.bytes",
                    "bytes() received invalid arguments",
                ),
            )
        constraints: list[z3.BoolRef] = [constraint]
        if not args and "source" not in kwargs:
            return ModelResult(value=symbolic_bytes_literal(b""))
        source = args[0] if args else kwargs["source"]
        has_encoding = len(args) > 1 or "encoding" in kwargs
        has_errors = len(args) > 2 or "errors" in kwargs
        if has_errors and not has_encoding:
            return ModelResult(
                value=result,
                constraints=constraints,
                side_effects=SideEffects.type_error(
                    "builtins.bytes",
                    "bytes() errors requires an encoding",
                ),
            )
        if has_encoding and source is not None and not isinstance(source, (str, SymbolicString)):
            return ModelResult(
                value=result,
                constraints=constraints,
                side_effects=SideEffects.type_error(
                    "builtins.bytes",
                    "bytes() encoding requires a string source",
                ),
            )
        if not has_encoding and isinstance(source, (str, SymbolicString)):
            return ModelResult(
                value=result,
                constraints=constraints,
                side_effects=SideEffects.type_error(
                    "builtins.bytes",
                    "bytes() string argument requires an encoding",
                ),
            )
        if source is None:
            return ModelResult(
                value=result,
                constraints=constraints,
                side_effects=SideEffects.type_error(
                    "builtins.bytes",
                    "bytes() cannot convert None to bytes",
                ),
            )
        if not has_encoding and isinstance(source, float):
            return ModelResult(
                value=result,
                constraints=constraints,
                side_effects=SideEffects.type_error(
                    "builtins.bytes",
                    "bytes() requires an integer or iterable source",
                ),
            )
        count = exact_byte_count(source)
        if count is not None and count < 0:
            return ModelResult(
                value=result,
                constraints=constraints,
                side_effects=SideEffects.value_error("builtins.bytes", "negative count"),
            )
        if count is not None:
            result = dataclasses.replace(
                result,
                z3_array=z3.K(z3.IntSort(), z3.IntVal(0)),
            )
            return ModelResult(
                value=result,
                constraints=[constraint, result.z3_len == count],
            )
        if has_encoding:
            encoding_arg = constructor_arg(args, kwargs, 1, "encoding")
            errors_arg = constructor_arg(args, kwargs, 2, "errors", "strict")
            if definitely_invalid_text_argument(encoding_arg) or definitely_invalid_text_argument(
                errors_arg,
            ):
                return ModelResult(
                    value=result,
                    constraints=constraints,
                    side_effects=SideEffects.type_error(
                        "builtins.bytes",
                        "bytes() encoding and errors must be strings",
                    ),
                )
            encoded = exact_encoded_byte_values(
                source,
                encoding_arg,
                errors_arg,
            )
            if encoded is not None:
                return ModelResult(value=symbolic_bytes_literal(bytes(encoded)))
        if not has_encoding:
            exact_items = exact_byte_values(source, state)
            if exact_items is not None:
                return ModelResult(
                    value=symbolic_bytes_literal(bytes(exact_items)),
                    side_effects=iterator_exhaustion_side_effect(
                        SymbolicObject.resolve(source, state),
                        state,
                    )
                    or {},
                )
            retained_items = exact_byte_items(source, state)
            if retained_items is not None:
                return ModelResult(
                    value=symbolic_bytes_items(retained_items),
                    side_effects=iterator_exhaustion_side_effect(
                        SymbolicObject.resolve(source, state),
                        state,
                    )
                    or {},
                )
            item_error = exact_byte_values_error(source, state)
            if item_error is not None:
                return ModelResult(
                    value=result,
                    constraints=constraints,
                    side_effects=(
                        SideEffects.value_error("builtins.bytes", "bytes must be in range(0, 256)")
                        if item_error == "value"
                        else SideEffects.type_error(
                            "builtins.bytes",
                            "bytes() iterable contains a non-integer item",
                        )
                    ),
                )
        val = DynamicBuiltinOps.constructor_len(SymbolicObject.resolve(source, state))
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
        result = dataclasses.replace(result, _type="bytearray")
        if invalid_binary_constructor_call(args, kwargs):
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.bytearray",
                    "bytearray() received invalid arguments",
                ),
            )
        constraints: list[z3.BoolRef] = [constraint]
        if not args and "source" not in kwargs:
            return ModelResult(value=_bytearray_literal([]))
        source = args[0] if args else kwargs["source"]
        has_encoding = len(args) > 1 or "encoding" in kwargs
        has_errors = len(args) > 2 or "errors" in kwargs
        if has_errors and not has_encoding:
            return ModelResult(
                value=result,
                constraints=constraints,
                side_effects=SideEffects.type_error(
                    "builtins.bytearray",
                    "bytearray() errors requires an encoding",
                ),
            )
        if has_encoding and source is not None and not isinstance(source, (str, SymbolicString)):
            return ModelResult(
                value=result,
                constraints=constraints,
                side_effects=SideEffects.type_error(
                    "builtins.bytearray",
                    "bytearray() encoding requires a string source",
                ),
            )
        if not has_encoding and isinstance(source, (str, SymbolicString)):
            return ModelResult(
                value=result,
                constraints=constraints,
                side_effects=SideEffects.type_error(
                    "builtins.bytearray",
                    "bytearray() string argument requires an encoding",
                ),
            )
        if source is None:
            return ModelResult(
                value=result,
                constraints=constraints,
                side_effects=SideEffects.type_error(
                    "builtins.bytearray",
                    "bytearray() cannot convert None",
                ),
            )
        if not has_encoding and isinstance(source, float):
            return ModelResult(
                value=result,
                constraints=constraints,
                side_effects=SideEffects.type_error(
                    "builtins.bytearray",
                    "bytearray() requires an integer or iterable source",
                ),
            )
        count = exact_byte_count(source)
        if count is not None and count < 0:
            return ModelResult(
                value=result,
                constraints=constraints,
                side_effects=SideEffects.value_error("builtins.bytearray", "negative count"),
            )
        if count is not None:
            if count <= _EAGER_ZERO_BYTEARRAY_LIMIT:
                return ModelResult(value=_bytearray_literal([0] * count))
            result = dataclasses.replace(
                result,
                z3_array=z3.K(z3.IntSort(), z3.IntVal(0)),
            )
            return ModelResult(
                value=result,
                constraints=[constraint, result.z3_len == count],
            )
        if has_encoding:
            encoding_arg = constructor_arg(args, kwargs, 1, "encoding")
            errors_arg = constructor_arg(args, kwargs, 2, "errors", "strict")
            if definitely_invalid_text_argument(encoding_arg) or definitely_invalid_text_argument(
                errors_arg,
            ):
                return ModelResult(
                    value=result,
                    constraints=constraints,
                    side_effects=SideEffects.type_error(
                        "builtins.bytearray",
                        "bytearray() encoding and errors must be strings",
                    ),
                )
            encoded = exact_encoded_byte_values(
                source,
                encoding_arg,
                errors_arg,
            )
            if encoded is not None:
                return ModelResult(value=_bytearray_literal(encoded))
        if not has_encoding:
            exact_items = exact_byte_values(source, state)
            if exact_items is not None:
                return ModelResult(
                    value=_bytearray_literal(exact_items),
                    side_effects=iterator_exhaustion_side_effect(
                        SymbolicObject.resolve(source, state),
                        state,
                    )
                    or {},
                )
            retained_items = exact_byte_items(source, state)
            if retained_items is not None:
                return ModelResult(
                    value=_bytearray_retained_items(retained_items),
                    side_effects=iterator_exhaustion_side_effect(
                        SymbolicObject.resolve(source, state),
                        state,
                    )
                    or {},
                )
            item_error = exact_byte_values_error(source, state)
            if item_error is not None:
                return ModelResult(
                    value=result,
                    constraints=constraints,
                    side_effects=(
                        SideEffects.value_error(
                            "builtins.bytearray",
                            "byte must be in range(0, 256)",
                        )
                        if item_error == "value"
                        else SideEffects.type_error(
                            "builtins.bytearray",
                            "bytearray() iterable contains a non-integer item",
                        )
                    ),
                )
        val = DynamicBuiltinOps.constructor_len(SymbolicObject.resolve(source, state))
        if val is not None:
            constraints.append(result.z3_len == val)
            constraints.append(val >= 0)
        return ModelResult(value=result, constraints=constraints)


def _bytearray_literal(values: list[int]) -> SymbolicList:
    return dataclasses.replace(SymbolicList.from_const(values), _type="bytearray")


def _bytearray_retained_items(values: list[StackValue]) -> SymbolicList:
    return dataclasses.replace(SymbolicList.from_const(values), _type="bytearray")
