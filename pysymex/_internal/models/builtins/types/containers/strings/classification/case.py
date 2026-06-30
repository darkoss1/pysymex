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

"""Case-classification symbolic string models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.models.builtins.types.containers.strings.shared import (
    FunctionModel,
    ModelResult,
    SymbolicValue,
    z3,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def _exact_classification_result(args: list[StackValue], method_name: str) -> bool | None:
    literal = SymbolicString.concrete_literal(args[0])
    if literal is None:
        return None
    return bool(getattr(literal, method_name)())


class StrIslowerModel(FunctionModel):
    """Model for str.islower()."""

    name = "islower"
    qualname = "str.islower"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        exact = _exact_classification_result(args, "islower")
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        original = SymbolicString.resolve(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic_bool(f"islower_{state.pc}")
        constraints = [constraint]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class StrIsupperModel(FunctionModel):
    """Model for str.isupper()."""

    name = "isupper"
    qualname = "str.isupper"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        exact = _exact_classification_result(args, "isupper")
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        original = SymbolicString.resolve(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic_bool(f"isupper_{state.pc}")
        constraints = [constraint]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class StrIstitleModel(FunctionModel):
    """Model for str.istitle()."""

    name = "istitle"
    qualname = "str.istitle"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        exact = _exact_classification_result(args, "istitle")
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        original = SymbolicString.resolve(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic_bool(f"istitle_{state.pc}")
        constraints = [constraint]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)
