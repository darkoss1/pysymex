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

"""Model for builtin ``next()``."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.constants import Z3_ZERO
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.havoc import HavocValue
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.common.dynamic import DynamicBuiltinOps
from pysymex._internal.models.builtins.iteration.consumption import (
    iterator_mutation_side_effect,
    iterator_size_change_runtime_error,
)
from pysymex._internal.models.builtins.iteration.ops import (
    BuiltinIteratorOps,
)
from pysymex._internal.models.builtins.iteration.sources import IterationSources
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult, SideEffects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class NextModel(FunctionModel):
    """Model for next()."""

    name = "next"
    qualname = "builtins.next"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {1, 2} or kwargs:
            return BuiltinIteratorOps.arity_type_error("next", args, state)
        if args:
            iterator = SymbolicObject.resolve(args[0], state)
            has_default = len(args) > 1
            default = args[1] if has_default else None
            if isinstance(iterator, SymbolicIterator) and iterator.is_generator:
                result, constraint = HavocValue.havoc(f"havoc_generator_next_{state.pc}")
                return ModelResult(value=result, constraints=[constraint])
            if isinstance(iterator, SymbolicIterator):
                if iterator_size_change_runtime_error(iterator, state):
                    result, constraint = SymbolicValue.symbolic(f"next_{state.pc}")
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects=_runtime_error_side_effect(
                            BuiltinIteratorOps.iterator_size_change_message(iterator),
                        ),
                    )
                remaining_items = IterationSources.remaining_iterator_items(iterator, state)
                if remaining_items is not None:
                    if remaining_items:
                        return ModelResult(
                            value=remaining_items[0],
                            side_effects=iterator_mutation_side_effect(
                                iterator,
                                iterator.advance(),
                            ),
                        )
                    exhausted = iterator.exhaust()
                    if has_default:
                        return ModelResult(
                            value=default,
                            side_effects=iterator_mutation_side_effect(iterator, exhausted),
                        )
                    result, constraint = SymbolicValue.symbolic(f"next_{state.pc}")
                    side_effects = iterator_mutation_side_effect(iterator, exhausted)
                    side_effects.update(_stop_iteration_side_effect())
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects=side_effects,
                    )
            if isinstance(iterator, SymbolicList):
                concrete_items = iterator.concrete_items
                if concrete_items:
                    return ModelResult(value=cast("StackValue", concrete_items[0]))
                if concrete_items == [] or z3.eq(iterator.z3_len, Z3_ZERO):
                    if len(args) > 1:
                        return ModelResult(value=default)
                    result, constraint = SymbolicValue.symbolic(f"next_{state.pc}")
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects=_stop_iteration_side_effect(),
                    )
            if isinstance(iterator, (list, tuple)):
                if iterator:
                    first = cast("list[StackValue] | tuple[StackValue, ...]", iterator)[0]
                    return ModelResult(value=first)
                if len(args) > 1:
                    return ModelResult(value=default)
                result, constraint = SymbolicValue.symbolic(f"next_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=_stop_iteration_side_effect(),
                )
            if DynamicBuiltinOps.iter_type_error(iterator):
                result, constraint = SymbolicValue.symbolic(f"next_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=SideEffects.type_error(
                        "builtins.next",
                        "next() argument is not an iterator",
                    ),
                )
        result, constraint = SymbolicValue.symbolic(f"next_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


def _stop_iteration_side_effect() -> dict[str, object]:
    return {
        "raised_exception": {
            "issue_kind": "UNHANDLED_EXCEPTION",
            "exception_type": "StopIteration",
            "message": "",
            "source": "builtins.next",
        },
    }


def _runtime_error_side_effect(message: str) -> dict[str, object]:
    return {
        "raised_exception": {
            "issue_kind": "UNHANDLED_EXCEPTION",
            "exception_type": "RuntimeError",
            "message": message,
            "source": "builtins.next",
        },
    }
