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

"""abs() builtin model."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.typed_results import (
    symbolic_int_result,
)

from ..base import FunctionModel, ModelResult
from .helpers import type_error_side_effect


class AbsModel(FunctionModel):
    """Model for abs()."""

    name = "abs"
    qualname = "builtins.abs"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply abs() model."""
        if len(args) != 1 or kwargs:
            result, constraint = SymbolicValue.symbolic(f"abs_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.abs",
                    f"abs() takes exactly one argument ({len(args)} given)",
                ),
            )
        x = args[0]
        if isinstance(x, SymbolicValue):
            result, constraints = symbolic_int_result(f"abs_{x.name}")
            constraints.append(result.z3_int == z3.If(x.z3_int >= 0, x.z3_int, -x.z3_int))
            return ModelResult(
                value=result,
                constraints=constraints,
            )
        if isinstance(x, (int, float, bool)):
            return ModelResult(value=abs(x))
        if x is None or isinstance(x, (str, bytes, SymbolicString, list, tuple, dict, set)):
            result, constraint = SymbolicValue.symbolic(f"abs_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.abs", "abs() argument does not define an absolute value"
                ),
            )
        return ModelResult(value=SymbolicValue.symbolic(f"abs_{state.pc}")[0])
