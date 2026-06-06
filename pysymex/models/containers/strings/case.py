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

from .shared import (
    FunctionModel,
    ModelResult,
    SymbolicString,
    concrete_string_literal,
    get_symbolic_string,
    method_type_error_result,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

"""Case-conversion symbolic string models."""


class StrLowerModel(FunctionModel):
    """Model for str.lower() - preserves string length.
    Relationship: len(s.lower()) == len(s)
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
            return method_type_error_result(self.qualname, state)
        literal = concrete_string_literal(args[0]) if args else None
        if literal is not None:
            return ModelResult(value=SymbolicString.from_const(literal.lower()))
        original = get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"lower_{state.pc}")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len == original.z3_len)
            constraints.append(result.z3_len >= 0)
        return ModelResult(value=result, constraints=constraints)


class StrUpperModel(FunctionModel):
    """Model for str.upper() - preserves string length.
    Relationship: len(s.upper()) == len(s)
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
            return method_type_error_result(self.qualname, state)
        literal = concrete_string_literal(args[0]) if args else None
        if literal is not None:
            return ModelResult(value=SymbolicString.from_const(literal.upper()))
        original = get_symbolic_string(args[0]) if args else None
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
            return method_type_error_result(self.qualname, state)
        literal = concrete_string_literal(args[0]) if args else None
        if literal is not None:
            return ModelResult(value=SymbolicString.from_const(literal.capitalize()))
        original = get_symbolic_string(args[0]) if args else None
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
            return method_type_error_result(self.qualname, state)
        literal = concrete_string_literal(args[0]) if args else None
        if literal is not None:
            return ModelResult(value=SymbolicString.from_const(literal.title()))
        original = get_symbolic_string(args[0]) if args else None
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
            return method_type_error_result(self.qualname, state)
        literal = concrete_string_literal(args[0]) if args else None
        if literal is not None:
            return ModelResult(value=SymbolicString.from_const(literal.swapcase()))
        original = get_symbolic_string(args[0]) if args else None
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
            return method_type_error_result(self.qualname, state)
        literal = concrete_string_literal(args[0]) if args else None
        if literal is not None:
            return ModelResult(value=SymbolicString.from_const(literal.casefold()))
        original = get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"casefold_{state.pc}")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len >= original.z3_len)
        return ModelResult(value=result, constraints=constraints)
