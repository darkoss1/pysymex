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

"""Symbolic models for the copy module."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


class CopyModel(FunctionModel):
    """Model for copy.copy()."""

    name = "copy"
    qualname = "copy.copy"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if args:
            return ModelResult(value=args[0])
        result, constraint = SymbolicValue.symbolic(f"copy_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class DeepcopyModel(FunctionModel):
    """Model for copy.deepcopy()."""

    name = "deepcopy"
    qualname = "copy.deepcopy"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if args:
            val = args[0]
            if isinstance(val, SymbolicValue):
                result, constraint = SymbolicValue.symbolic(f"deepcopy_{val.name}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.z3_int == val.z3_int],
                )
            if isinstance(val, SymbolicString):
                result, constraint = SymbolicString.symbolic(f"deepcopy_{val.name}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.z3_str == val.z3_str],
                )
            if isinstance(val, SymbolicList):
                result, constraint = SymbolicList.symbolic(f"deepcopy_{val.name}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.z3_len == val.z3_len],
                )
        result, constraint = SymbolicValue.symbolic(f"deepcopy_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


copy_models = [
    CopyModel(),
    DeepcopyModel(),
]


__all__ = ["CopyModel", "DeepcopyModel", "copy_models"]
