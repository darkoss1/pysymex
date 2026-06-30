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

from pysymex._internal.core.constants import Z3_FALSE
from pysymex._internal.core.types.containers.set_retention import replace_exact_set_value
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.iteration.consumption import iterator_exhaustion_side_effect
from pysymex._internal.models.builtins.iteration.hashability import (
    contains_definitely_unhashable_item,
)
from pysymex._internal.models.builtins.iteration.sources import IterationSources
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult, SideEffects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

"""Set constructor symbolic model."""


class SetConstructorModel(FunctionModel):
    """Model for set constructor."""

    name = "set"
    qualname = "builtins.set"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply the set constructor model."""
        result, constraint = SymbolicValue.symbolic(f"set_{state.pc}")
        if len(args) > 1 or kwargs:
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.set",
                    "set() accepts at most one argument",
                ),
            )
        result.set_runtime_type("set")
        if not args:
            return ModelResult(value=_exact_set_value(set()))
        source = SymbolicObject.resolve(args[0], state)
        if source is None or isinstance(source, (int, float, bool)):
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.set",
                    "set() argument is not iterable",
                ),
            )
        direct_items = IterationSources.iterable_items(source, state)
        if direct_items is not None:
            iterator_side_effects = iterator_exhaustion_side_effect(source, state)
            if contains_definitely_unhashable_item(direct_items, state):
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=SideEffects.type_error(
                        "builtins.set",
                        "set() argument contains an unhashable item",
                    ),
                )
            try:
                return ModelResult(
                    value=_exact_set_value(set(direct_items)),
                    side_effects=iterator_side_effects or {},
                )
            except TypeError:
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=SideEffects.type_error(
                        "builtins.set",
                        "set() argument contains an unhashable item",
                    ),
                )
        return ModelResult(value=result, constraints=[constraint, result.z3_int >= 0])


def _exact_set_value(values: set[object]) -> SymbolicValue:
    result = SymbolicValue.from_const(values)
    result.set_runtime_type("set")
    result.is_none = Z3_FALSE
    replace_exact_set_value(result, values)
    return result
