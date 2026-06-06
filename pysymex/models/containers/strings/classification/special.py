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

"""Special-case symbolic string classification models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..shared import (
    FunctionModel,
    ModelResult,
    SymbolicIsasciiModel,
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


class StrIsprintableModel(FunctionModel):
    """Model for str.isprintable()."""

    name = "isprintable"
    qualname = "str.isprintable"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return method_type_error_result(self.qualname, state)
        exact = _exact_classification_result(args, "isprintable")
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        original = get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"isprintable_{state.pc}")
        constraints = [constraint, result.is_bool]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, result.z3_bool))
        return ModelResult(value=result, constraints=constraints)


class StrIsidentifierModel(FunctionModel):
    """Model for str.isidentifier()."""

    name = "isidentifier"
    qualname = "str.isidentifier"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return method_type_error_result(self.qualname, state)
        exact = _exact_classification_result(args, "isidentifier")
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        original = get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"isidentifier_{state.pc}")
        constraints = [constraint, result.is_bool]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class StrIsasciiModel(SymbolicIsasciiModel):
    name = "isascii"
    qualname = "str.isascii"
