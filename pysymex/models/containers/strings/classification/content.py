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

"""Content-classification symbolic string models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..shared import (
    FunctionModel,
    ModelResult,
    SymbolicValue,
    concrete_string_literal,
    get_symbolic_string,
    method_type_error_result,
    z3,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


def _exact_classification_result(args: list[StackValue], method_name: str) -> bool | None:
    literal = concrete_string_literal(args[0])
    if literal is None:
        return None
    return bool(getattr(literal, method_name)())


class StrIsdigitModel(FunctionModel):
    """Model for str.isdigit() - true only if non-empty and all digits."""

    name = "isdigit"
    qualname = "str.isdigit"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return method_type_error_result(self.qualname, state)
        exact = _exact_classification_result(args, "isdigit")
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        original = get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"isdigit_{state.pc}")
        constraints = [constraint, result.is_bool]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class StrIsalphaModel(FunctionModel):
    """Model for str.isalpha() - true only if non-empty and all alphabetic."""

    name = "isalpha"
    qualname = "str.isalpha"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return method_type_error_result(self.qualname, state)
        exact = _exact_classification_result(args, "isalpha")
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        original = get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"isalpha_{state.pc}")
        constraints = [constraint, result.is_bool]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class StrIsalnumModel(FunctionModel):
    """Model for str.isalnum() - true only if non-empty and all alphanumeric."""

    name = "isalnum"
    qualname = "str.isalnum"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return method_type_error_result(self.qualname, state)
        exact = _exact_classification_result(args, "isalnum")
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        original = get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"isalnum_{state.pc}")
        constraints = [constraint, result.is_bool]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class StrIsspaceModel(FunctionModel):
    """Model for str.isspace() - true only if non-empty and all whitespace."""

    name = "isspace"
    qualname = "str.isspace"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return method_type_error_result(self.qualname, state)
        exact = _exact_classification_result(args, "isspace")
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        original = get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"isspace_{state.pc}")
        constraints = [constraint, result.is_bool]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class StrIsdecimalModel(FunctionModel):
    """Model for str.isdecimal()."""

    name = "isdecimal"
    qualname = "str.isdecimal"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return method_type_error_result(self.qualname, state)
        exact = _exact_classification_result(args, "isdecimal")
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        original = get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"isdecimal_{state.pc}")
        constraints = [constraint, result.is_bool]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class StrIsnumericModel(FunctionModel):
    """Model for str.isnumeric()."""

    name = "isnumeric"
    qualname = "str.isnumeric"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return method_type_error_result(self.qualname, state)
        exact = _exact_classification_result(args, "isnumeric")
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        original = get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"isnumeric_{state.pc}")
        constraints = [constraint, result.is_bool]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)
