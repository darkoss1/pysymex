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

from pysymex.core.constants import Z3_TRUE

from ..shared import (
    FunctionModel,
    ModelResult,
    SymbolicValue,
    bytes_type_error_result,
    concrete_bytes_literal,
    get_symbolic_bytes,
    z3,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


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
            return bytes_type_error_result(self.name, state)
        exact = _exact_count_result(args)
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_count_{state.pc}")
        constraints = [constraint, result.is_int, result.z3_int >= 0]
        if b is not None:
            constraints.append(result.z3_int <= b.z3_len)
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
            return bytes_type_error_result(self.name, state)
        if _contains_invalid_int_needle(args[1]):
            return _value_error_result("bytes_contains", "byte must be in range(0, 256)", state)
        if _contains_invalid_type_needle(args[1]):
            return bytes_type_error_result(self.name, state)
        exact = _exact_contains_result(args)
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_contains_{state.pc}")
        constraints = [constraint, result.is_bool]
        if b is not None:
            constraints.append(z3.Implies(b.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


def _exact_count_result(args: list[StackValue]) -> int | None:
    source = concrete_bytes_literal(args[0])
    needle = concrete_bytes_literal(args[1]) if len(args) > 1 else None
    slice_args = _exact_slice_args(args[2:])
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
    if isinstance(value, SymbolicValue) and value.value is None:
        return False
    return True


def _concrete_byte_int(value: StackValue) -> int | None:
    concrete = value.value if isinstance(value, SymbolicValue) else value
    if isinstance(concrete, bool):
        return int(concrete)
    if isinstance(concrete, int) and 0 <= concrete <= 255:
        return concrete
    return None


def _value_error_result(name: str, message: str, state: VMState) -> ModelResult:
    result, constraint = SymbolicValue.symbolic(f"{name}_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint, result.is_bool],
        side_effects={
            "potential_exception": {
                "type": "ValueError",
                "condition": Z3_TRUE,
                "message": message,
            }
        },
    )


def _exact_slice_args(args: list[StackValue]) -> list[int | None] | None:
    slice_args: list[int | None] = []
    for value in args:
        supported, concrete_index = _concrete_optional_int(value)
        if not supported:
            return None
        slice_args.append(concrete_index)
    return slice_args


def _concrete_optional_int(value: object) -> tuple[bool, int | None]:
    if isinstance(value, SymbolicValue):
        value = value.value
    if value is None:
        return True, None
    if isinstance(value, bool):
        return True, int(value)
    if isinstance(value, int):
        return True, value
    return False, None
