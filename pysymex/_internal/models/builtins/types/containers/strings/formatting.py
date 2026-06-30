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

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.scalars.strings import SymbolicString

from .shared import (
    FunctionModel,
    ModelResult,
    SymbolicValue,
    z3,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

"""Formatting and padding symbolic string models."""


class StrFormatModel(FunctionModel):
    """Model for str.format() - result length relationship.
    Result length >= format string length - placeholder lengths.
    """

    name = "format"
    qualname = "str.format"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"format_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        return ModelResult(value=result, constraints=constraints)


class StrCenterModel(FunctionModel):
    """Model for str.center(width) - pads string to width.
    Relationship: len(result) == max(width, len(original)).
    """

    name = "center"
    qualname = "str.center"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3} or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        exact = _exact_padding_result(args, "center", self.qualname, state)
        if exact is not None:
            return exact
        original = SymbolicString.resolve(args[0]) if args else None
        width = args[1] if len(args) > 1 else None
        result, base_constraint = SymbolicString.symbolic(f"center_{state.pc}")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len >= original.z3_len)
            if isinstance(width, int):
                constraints.append(
                    z3.Or(
                        result.z3_len == ConstraintValues.int(width),
                        result.z3_len == original.z3_len,
                    ),
                )
            elif isinstance(width, SymbolicValue):
                constraints.append(
                    z3.Or(result.z3_len == width.z3_int, result.z3_len == original.z3_len),
                )
        return ModelResult(value=result, constraints=constraints)


class StrLjustModel(FunctionModel):
    """Model for str.ljust(width) - left justify."""

    name = "ljust"
    qualname = "str.ljust"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3} or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        exact = _exact_padding_result(args, "ljust", self.qualname, state)
        if exact is not None:
            return exact
        original = SymbolicString.resolve(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"ljust_{state.pc}")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len >= original.z3_len)
            constraints.append(z3.PrefixOf(original.z3_str, result.z3_str))
        return ModelResult(value=result, constraints=constraints)


class StrRjustModel(FunctionModel):
    """Model for str.rjust(width) - right justify."""

    name = "rjust"
    qualname = "str.rjust"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3} or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        exact = _exact_padding_result(args, "rjust", self.qualname, state)
        if exact is not None:
            return exact
        original = SymbolicString.resolve(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"rjust_{state.pc}")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len >= original.z3_len)
            constraints.append(z3.SuffixOf(original.z3_str, result.z3_str))
        return ModelResult(value=result, constraints=constraints)


class StrZfillModel(FunctionModel):
    """Model for str.zfill(width) - zero-pad on left."""

    name = "zfill"
    qualname = "str.zfill"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        literal = SymbolicString.concrete_literal(args[0]) if args else None
        width = _concrete_int(args[1]) if len(args) > 1 else None
        if literal is not None and width is not None:
            return ModelResult(value=SymbolicString.from_const(literal.zfill(width)))
        if width is None and _definitely_not_int(args[1]):
            return ModelResult.method_type_error(
                self.qualname,
                state,
                message=(
                    f"'{type(_unwrap_symbolic_value(args[1])).__name__}' object "
                    "cannot be interpreted as an integer"
                ),
            )
        original = SymbolicString.resolve(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"zfill_{state.pc}")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len >= original.z3_len)
        return ModelResult(value=result, constraints=constraints)


class StrFormatMapModel(FunctionModel):
    """Model for str.format_map(mapping)."""

    name = "format_map"
    qualname = "str.format_map"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        result, base_constraint = SymbolicString.symbolic(f"format_map_{state.pc}")
        return ModelResult(value=result, constraints=[base_constraint])


def _exact_padding_result(
    args: list[StackValue],
    method_name: str,
    qualname: str,
    state: VMState,
) -> ModelResult | None:
    literal = SymbolicString.concrete_literal(args[0])
    width = _concrete_int(args[1]) if len(args) > 1 else None
    if width is None and len(args) > 1 and _definitely_not_int(args[1]):
        return ModelResult.method_type_error(
            qualname,
            state,
            message=f"'{type(_unwrap_symbolic_value(args[1])).__name__}' object cannot be interpreted as an integer",
        )

    fillchar = " "
    if len(args) == 3:
        concrete_fillchar = SymbolicString.concrete_literal(args[2])
        if concrete_fillchar is None and _definitely_not_string(args[2]):
            return ModelResult.method_type_error(
                qualname,
                state,
                message=(
                    "The fill character must be a unicode character, "
                    f"not {type(_unwrap_symbolic_value(args[2])).__name__}"
                ),
            )
        if concrete_fillchar is not None:
            if len(concrete_fillchar) != 1:
                return ModelResult.method_type_error(
                    qualname,
                    state,
                    message="The fill character must be exactly one character long",
                )
            fillchar = concrete_fillchar
        elif literal is not None and width is not None:
            return None

    if literal is None or width is None:
        return None
    padded = getattr(literal, method_name)(width, fillchar)
    return ModelResult(value=SymbolicString.from_const(padded))


def _concrete_int(value: object) -> int | None:
    if isinstance(value, SymbolicValue):
        value = value.value
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return None


def _definitely_not_int(value: object) -> bool:
    if _is_none_value(value):
        return True
    if isinstance(value, SymbolicValue):
        value = value.value
    return isinstance(value, (str, bytes, float, SymbolicString))


def _definitely_not_string(value: object) -> bool:
    if _is_none_value(value):
        return True
    if isinstance(value, SymbolicValue):
        value = value.value
        if value is None:
            return False
    return not isinstance(value, (str, SymbolicString))


def _unwrap_symbolic_value(value: object) -> object:
    if _is_none_value(value):
        return None
    if isinstance(value, SymbolicValue):
        return value.value
    return value


def _is_none_value(value: object) -> bool:
    return (
        value is None
        or isinstance(value, SymbolicNoneType)
        or isinstance(value, SymbolicValue)
        and z3.is_true(value.is_none)
    )
