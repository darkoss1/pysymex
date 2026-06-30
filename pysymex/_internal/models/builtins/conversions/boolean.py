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

"""bool() builtin model."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.models.contracts.results import SideEffects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult


def _length_truth_result(name: str, length: z3.ArithRef) -> ModelResult:
    truth = simplify_expr(length != 0)
    if z3.is_true(truth):
        return ModelResult(value=True)
    if z3.is_false(truth):
        return ModelResult(value=False)
    result, constraints = ModelResult.symbolic_bool(f"bool_{name}")
    constraints.append(result.z3_bool == truth)
    return ModelResult(value=result, constraints=constraints)


class BoolModel(FunctionModel):
    """Model for bool()."""

    name = "bool"
    qualname = "builtins.bool"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) > 1 or kwargs:
            result, constraint = SymbolicValue.symbolic(f"bool_invalid_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.bool",
                    "bool() received too many arguments",
                ),
            )
        if not args:
            return ModelResult(value=False)
        value = SymbolicObject.resolve(args[0], state)
        if isinstance(value, SymbolicString):
            return _length_truth_result(value.name, value.z3_len)
        if isinstance(value, SymbolicList):
            return _length_truth_result(value.name, value.z3_len)
        if isinstance(value, SymbolicDict):
            return _length_truth_result(value.name, value.z3_len)
        if isinstance(value, SymbolicValue):
            if isinstance(value.value, (int, float, bool)):
                return ModelResult(value=bool(value.value))
            if value.affinity_type == "str" and z3.is_string_value(value.z3_str):
                return ModelResult(value=bool(value.z3_str.as_string()))
            result, constraints = ModelResult.symbolic_bool(f"bool_{value.name}")
            constraints.append(result.z3_bool == value.could_be_truthy())
            return ModelResult(value=result, constraints=constraints)
        try:
            return ModelResult(value=bool(value))
        except (TypeError, ValueError, RecursionError):
            return ModelResult.bool(f"bool_{state.pc}")
