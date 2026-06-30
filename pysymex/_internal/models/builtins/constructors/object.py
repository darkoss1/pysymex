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

"""Memoryview and object constructor builtin models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.models.contracts.results import SideEffects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult


@dataclass(frozen=True, slots=True)
class ModeledMemoryView:
    """Retained source for exact memoryview method modeling."""

    source: StackValue


class MemoryviewModel(FunctionModel):
    """Model for memoryview()."""

    name = "memoryview"
    qualname = "builtins.memoryview"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"memoryview_{state.pc}")
        if len(args) != 1 or kwargs:
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.memoryview",
                    f"memoryview() received invalid positional argument count: {len(args)}",
                ),
            )
        if args[0] is None or isinstance(
            args[0],
            (
                int,
                float,
                bool,
                str,
                SymbolicString,
                list,
                tuple,
                dict,
                set,
                frozenset,
            ),
        ):
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.memoryview",
                    "memoryview() requires a bytes-like object",
                ),
            )
        result.is_obj = Z3_TRUE
        result.is_none = Z3_FALSE
        result.affinity_type = "memoryview"
        result.attach_modeled_object(ModeledMemoryView(source=args[0]))
        return ModelResult(value=result, constraints=[constraint])


class ObjectModel(FunctionModel):
    """Model for object() with definite object type and fresh identity."""

    name = "object"
    qualname = "builtins.object"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"object_{state.pc}")
        if args or kwargs:
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.object",
                    "object() takes no arguments",
                ),
            )
        result.is_obj = Z3_TRUE
        result.is_none = Z3_FALSE
        result.affinity_type = "obj"
        return ModelResult(value=result, constraints=[constraint])
