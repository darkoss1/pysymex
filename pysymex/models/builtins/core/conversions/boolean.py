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

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.typing import StackValue

from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.typed_results import model_bool_result, symbolic_bool_result

from ...base import FunctionModel, ModelResult
from ..helpers import type_error_side_effect


def _length_truth_result(name: str, length: z3.ArithRef) -> ModelResult:
    truth = z3.simplify(length != 0)
    if z3.is_true(truth):
        return ModelResult(value=True)
    if z3.is_false(truth):
        return ModelResult(value=False)
    result, constraints = symbolic_bool_result(f"bool_{name}")
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
                side_effects=type_error_side_effect(
                    "builtins.bool", "bool() received too many arguments"
                ),
            )
        if not args:
            return ModelResult(value=False)
        value = args[0]
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
            result, constraints = symbolic_bool_result(f"bool_{value.name}")
            constraints.append(result.z3_bool == value.could_be_truthy())
            return ModelResult(value=result, constraints=constraints)
        try:
            return ModelResult(value=bool(value))
        except (TypeError, ValueError, RecursionError):
            return model_bool_result(f"bool_{state.pc}")
