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

"""Index-search symbolic bytes models."""

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


class BytesFindModel(FunctionModel):
    """Model for bytes.find(sub)."""

    name = "find"
    qualname = "bytes.find"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3, 4} or kwargs:
            return bytes_type_error_result(self.name, state)
        exact = _exact_find_result(args, reverse=False)
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_find_{state.pc}")
        constraints = [constraint, result.is_int, result.z3_int >= -1]
        if b is not None:
            constraints.append(result.z3_int < b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytesRfindModel(FunctionModel):
    """Model for bytes.rfind(sub)."""

    name = "rfind"
    qualname = "bytes.rfind"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3, 4} or kwargs:
            return bytes_type_error_result(self.name, state)
        exact = _exact_find_result(args, reverse=True)
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_rfind_{state.pc}")
        constraints = [constraint, result.is_int, result.z3_int >= -1]
        if b is not None:
            constraints.append(result.z3_int < b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytesIndexModel(FunctionModel):
    """Model for bytes.index(sub)."""

    name = "index"
    qualname = "bytes.index"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3, 4} or kwargs:
            return bytes_type_error_result(self.name, state)
        exact = _exact_find_result(args, reverse=False)
        if exact is not None:
            side_effects = _value_error_side_effect(exact, "subsection not found")
            return ModelResult(value=SymbolicValue.from_const(exact), side_effects=side_effects)
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_index_{state.pc}")
        constraints = [constraint, result.is_int, result.z3_int >= 0]
        side_effects: dict[str, object] = {
            "potential_exception": {
                "type": "ValueError",
                "condition": z3.Bool(f"bytes_index_missing_{state.pc}"),
                "message": "subsection not found",
            }
        }
        if b is not None:
            constraints.append(result.z3_int < b.z3_len)
        return ModelResult(value=result, constraints=constraints, side_effects=side_effects)


class BytesRindexModel(FunctionModel):
    """Model for bytes.rindex(sub)."""

    name = "rindex"
    qualname = "bytes.rindex"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3, 4} or kwargs:
            return bytes_type_error_result(self.name, state)
        exact = _exact_find_result(args, reverse=True)
        if exact is not None:
            side_effects = _value_error_side_effect(exact, "subsection not found")
            return ModelResult(value=SymbolicValue.from_const(exact), side_effects=side_effects)
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_rindex_{state.pc}")
        constraints = [constraint, result.is_int, result.z3_int >= 0]
        side_effects: dict[str, object] = {
            "potential_exception": {
                "type": "ValueError",
                "condition": z3.Bool(f"bytes_rindex_missing_{state.pc}"),
                "message": "subsection not found",
            }
        }
        if b is not None:
            constraints.append(result.z3_int < b.z3_len)
        return ModelResult(value=result, constraints=constraints, side_effects=side_effects)


def _exact_find_result(args: list[StackValue], *, reverse: bool) -> int | None:
    source = concrete_bytes_literal(args[0])
    needle = concrete_bytes_literal(args[1]) if len(args) > 1 else None
    slice_args = _exact_slice_args(args[2:])
    if source is None or needle is None or slice_args is None:
        return None
    return source.rfind(needle, *slice_args) if reverse else source.find(needle, *slice_args)


def _value_error_side_effect(result: int, message: str) -> dict[str, object]:
    if result != -1:
        return {}
    return {
        "potential_exception": {
            "type": "ValueError",
            "condition": Z3_TRUE,
            "message": message,
        }
    }


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
