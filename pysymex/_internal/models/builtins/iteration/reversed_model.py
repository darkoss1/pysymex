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

"""Model for builtin ``reversed()``."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.containers.sets import SymbolicSet
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.models.builtins.common.dynamic import DynamicBuiltinOps
from pysymex._internal.models.builtins.iteration.ops import (
    BuiltinIteratorOps,
)
from pysymex._internal.models.builtins.iteration.sources import IterationSources
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult, SideEffects

if TYPE_CHECKING:
    from collections.abc import Sequence

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class ReversedModel(FunctionModel):
    """Model for reversed()."""

    name = "reversed"
    qualname = "builtins.reversed"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return BuiltinIteratorOps.arity_type_error("reversed", args, state)
        val = SymbolicObject.resolve(args[0], state)
        source = IterationSources.payload(val)
        if _definite_reversed_type_error(source):
            result, constraint = SymbolicList.symbolic(f"reversed_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.reversed",
                    "reversed() argument is not reversible",
                ),
            )
        concrete_items = IterationSources.iterable_items(source, state)
        if concrete_items is not None and _is_live_reversible_source(source):
            return ModelResult(
                value=SymbolicIterator(
                    f"reversed_{state.pc}",
                    source,
                    reverse=True,
                    source_size=BuiltinIteratorOps.iterator_source_size(source, state),
                    size_change_raises=BuiltinIteratorOps.iterator_size_change_raises(source),
                ),
            )
        if concrete_items is not None and _is_exact_reversible_source(source):
            exact_reversed_items = list(reversed(concrete_items))
            return ModelResult(value=SymbolicIterator(f"reversed_{state.pc}", exact_reversed_items))
        if isinstance(val, SymbolicList):
            concrete_items = val.concrete_items
            if concrete_items is not None:
                symbolic_reversed_items = list(reversed(concrete_items))
                return ModelResult(
                    value=SymbolicIterator(f"reversed_{state.pc}", symbolic_reversed_items),
                )
            return ModelResult(
                value=SymbolicIterator(
                    f"reversed_{state.pc}",
                    val,
                    reverse=True,
                    source_size=BuiltinIteratorOps.iterator_source_size(val, state),
                    size_change_raises=BuiltinIteratorOps.iterator_size_change_raises(val),
                ),
            )
        if isinstance(val, (list, tuple, str)):
            sequence_reversed_items: list[StackValue] = list(
                reversed(cast("Sequence[StackValue]", val)),
            )
            return ModelResult(
                value=SymbolicIterator(f"reversed_{state.pc}", sequence_reversed_items),
            )
        if DynamicBuiltinOps.iter_type_error(val):
            result, constraint = SymbolicList.symbolic(f"reversed_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.reversed",
                    "reversed() argument is not reversible",
                ),
            )
        result, constraint = SymbolicList.symbolic(f"reversed_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


def _definite_reversed_type_error(value: object) -> bool:
    if isinstance(value, (set, frozenset, SymbolicSet)):
        return True
    return DynamicBuiltinOps.iter_type_error(value)


def _is_exact_reversible_source(value: object) -> bool:
    return isinstance(
        value,
        (
            list,
            tuple,
            str,
            bytes,
            bytearray,
            dict,
            SymbolicBytes,
            SymbolicDict,
            SymbolicList,
            SymbolicString,
        ),
    )


def _is_live_reversible_source(value: object) -> bool:
    return isinstance(value, (list, SymbolicList))
