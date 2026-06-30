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

"""Count and containment symbolic bytes models."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.types.containers.bytes_search import (
    bytes_slice_bounds_are_definitely_invalid,
    concrete_bytes_slice_args,
)
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.types.containers.bytes.shared import (
    concrete_bytes_literal,
    symbolic_bytes_length,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

_SLICE_INDEX_TYPE_ERROR = "slice indices must be integers or None or have an __index__ method"


class BytesCountModel(FunctionModel):
    """Model for bytes.count(sub)."""

    name = "count"
    qualname = "bytes.count"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3, 4} or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        if bytes_slice_bounds_are_definitely_invalid(args[2:]):
            return ModelResult.method_type_error(
                self.qualname,
                state,
                message=_SLICE_INDEX_TYPE_ERROR,
            )
        exact = _exact_count_result(args)
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        length = symbolic_bytes_length(args[0], state) if args else None
        empty_needle_result = _empty_needle_count_result(args, length, state)
        if empty_needle_result is not None:
            return empty_needle_result
        result, constraint = SymbolicValue.symbolic_int(f"bytes_count_{state.pc}")
        constraints = [constraint, result.z3_int >= 0]
        if length is not None:
            upper_bound = length + 1 if _concrete_needle(args) == b"" else length
            constraints.append(result.z3_int <= upper_bound)
        return ModelResult(value=result, constraints=constraints)


class BytesContainsModel(FunctionModel):
    """Model for bytes.__contains__(sub)."""

    name = "__contains__"
    qualname = "bytes.__contains__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        if _contains_invalid_int_needle(args[1]):
            return _value_error_result("bytes_contains", "byte must be in range(0, 256)", state)
        if _contains_invalid_type_needle(args[1]):
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        exact = _exact_contains_result(args)
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        if concrete_bytes_literal(args[1]) == b"":
            return ModelResult(value=SymbolicValue.from_const(True))
        length = symbolic_bytes_length(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic_bool(f"bytes_contains_{state.pc}")
        constraints = [constraint]
        if length is not None:
            constraints.append(z3.Implies(length == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


def _empty_needle_count_result(
    args: list[StackValue],
    length: z3.ArithRef | None,
    state: VMState,
) -> ModelResult | None:
    if len(args) != 2 or _concrete_needle(args) != b"" or length is None:
        return None
    result = SymbolicValue(
        _name=f"bytes_count_empty_{state.pc}",
        z3_int=length + 1,
        is_int=Z3_TRUE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
    )
    return ModelResult(value=result)


def _concrete_needle(args: list[StackValue]) -> bytes | None:
    return concrete_bytes_literal(args[1]) if len(args) > 1 else None


def _exact_count_result(args: list[StackValue]) -> int | None:
    source = concrete_bytes_literal(args[0])
    needle = concrete_bytes_literal(args[1]) if len(args) > 1 else None
    slice_args = concrete_bytes_slice_args(args[2:])
    if source is None or needle is None or slice_args is None:
        return None
    return source.count(needle, *slice_args)


def _exact_contains_result(args: list[StackValue]) -> bool | None:
    if len(args) != 2:
        return None
    source = concrete_bytes_literal(args[0])
    if source is None:
        return None
    needle_int = _concrete_byte_int(args[1])
    if needle_int is not None:
        return needle_int in source
    needle_bytes = concrete_bytes_literal(args[1])
    if needle_bytes is None:
        return None
    return needle_bytes in source


def _contains_invalid_int_needle(value: StackValue) -> bool:
    concrete = value.value if isinstance(value, SymbolicValue) else value
    return isinstance(concrete, int) and not isinstance(concrete, bool) and not 0 <= concrete <= 255


def _contains_invalid_type_needle(value: StackValue) -> bool:
    if _concrete_byte_int(value) is not None or concrete_bytes_literal(value) is not None:
        return False
    return not (isinstance(value, SymbolicValue) and value.value is None)


def _concrete_byte_int(value: StackValue) -> int | None:
    concrete = value.value if isinstance(value, SymbolicValue) else value
    if isinstance(concrete, bool):
        return int(concrete)
    if isinstance(concrete, int) and 0 <= concrete <= 255:
        return concrete
    return None


def _value_error_result(name: str, message: str, state: VMState) -> ModelResult:
    result, constraint = SymbolicValue.symbolic_bool(f"{name}_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects={
            "potential_exception": {
                "type": "ValueError",
                "condition": Z3_TRUE,
                "message": message,
            },
        },
    )
