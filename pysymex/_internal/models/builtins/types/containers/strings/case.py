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

from pysymex._internal.core.types.scalars.strings import SymbolicString

from .shared import (
    FunctionModel,
    ModelResult,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

"""Case-conversion symbolic string models."""


class StrLowerModel(FunctionModel):
    """Model for str.lower() - preserves string length.
    Relationship: len(s.lower()) == len(s).
    """

    name = "lower"
    qualname = "str.lower"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        literal = SymbolicString.concrete_literal(args[0]) if args else None
        if literal is not None:
            return ModelResult(value=SymbolicString.from_const(literal.lower()))
        original = SymbolicString.resolve(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"lower_{state.pc}")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len == original.z3_len)
            constraints.append(result.z3_len >= 0)
        return ModelResult(value=result, constraints=constraints)


class StrUpperModel(FunctionModel):
    """Model for str.upper() - preserves string length.
    Relationship: len(s.upper()) == len(s).
    """

    name = "upper"
    qualname = "str.upper"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        literal = SymbolicString.concrete_literal(args[0]) if args else None
        if literal is not None:
            return ModelResult(value=SymbolicString.from_const(literal.upper()))
        original = SymbolicString.resolve(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"upper_{state.pc}")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len == original.z3_len)
        return ModelResult(value=result, constraints=constraints)


class StrCapitalizeModel(FunctionModel):
    """Model for str.capitalize() - preserves string length."""

    name = "capitalize"
    qualname = "str.capitalize"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        literal = SymbolicString.concrete_literal(args[0]) if args else None
        if literal is not None:
            return ModelResult(value=SymbolicString.from_const(literal.capitalize()))
        original = SymbolicString.resolve(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"capitalize_{state.pc}")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len == original.z3_len)
        return ModelResult(value=result, constraints=constraints)


class StrTitleModel(FunctionModel):
    """Model for str.title() - preserves string length."""

    name = "title"
    qualname = "str.title"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        literal = SymbolicString.concrete_literal(args[0]) if args else None
        if literal is not None:
            return ModelResult(value=SymbolicString.from_const(literal.title()))
        original = SymbolicString.resolve(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"title_{state.pc}")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len == original.z3_len)
        return ModelResult(value=result, constraints=constraints)


class StrSwapcaseModel(FunctionModel):
    """Model for str.swapcase() - preserves string length."""

    name = "swapcase"
    qualname = "str.swapcase"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        literal = SymbolicString.concrete_literal(args[0]) if args else None
        if literal is not None:
            return ModelResult(value=SymbolicString.from_const(literal.swapcase()))
        original = SymbolicString.resolve(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"swapcase_{state.pc}")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len == original.z3_len)
        return ModelResult(value=result, constraints=constraints)


class StrCasefoldModel(FunctionModel):
    """Model for str.casefold() - aggressive lowercase.
    Length may change (e.g., German ß → ss).
    """

    name = "casefold"
    qualname = "str.casefold"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        literal = SymbolicString.concrete_literal(args[0]) if args else None
        if literal is not None:
            return ModelResult(value=SymbolicString.from_const(literal.casefold()))
        original = SymbolicString.resolve(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"casefold_{state.pc}")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len >= original.z3_len)
        return ModelResult(value=result, constraints=constraints)
