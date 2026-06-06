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

"""Tuple construction symbolic model."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, cast

from pysymex.core.types.containers.sequences import SymbolicIterator
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import FunctionModel, ModelResult
from pysymex.models.builtins.core.helpers import resolve_heap_object, type_error_side_effect
from pysymex.models.builtins.core.iterator_items import (
    concrete_iterable_items,
    exhausted_iterator,
    iterator_mutation_side_effect,
    remaining_concrete_iterator_items,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


class TupleModel(FunctionModel):
    """Model for tuple() constructor."""

    name = "tuple"
    qualname = "builtins.tuple"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply tuple() constructor."""
        result, constraint = SymbolicList.symbolic(f"tuple_{state.pc}")
        if len(args) > 1 or kwargs:
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.tuple", "tuple() accepts at most one argument"
                ),
            )
        if args and (args[0] is None or isinstance(args[0], (int, float, bool))):
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.tuple", "tuple() argument is not iterable"
                ),
            )
        if args:
            value = resolve_heap_object(args[0], state)
            if isinstance(value, SymbolicList):
                return ModelResult(value=value.copy())
            if isinstance(value, SymbolicIterator) and not value.is_generator:
                concrete_items = remaining_concrete_iterator_items(value, state)
                updated_iterator = exhausted_iterator(value, state)
                if concrete_items is not None and updated_iterator is not None:
                    copied = _copy_tuple_constructor_sequence(concrete_items)
                    if copied is not None:
                        return ModelResult(
                            value=copied,
                            side_effects=iterator_mutation_side_effect(
                                value,
                                updated_iterator,
                            ),
                        )
            concrete_items = concrete_iterable_items(value, state)
            if concrete_items is not None:
                copied = _copy_tuple_constructor_sequence(concrete_items)
                if copied is not None:
                    return ModelResult(value=copied)
            if isinstance(value, (list, tuple)):
                copied = _copy_tuple_constructor_sequence(cast("Sequence[object]", value))
                if copied is not None:
                    return ModelResult(value=copied)
        constraints = [constraint]
        if not args:
            constraints.append(result.z3_len == 0)
        return ModelResult(value=result, constraints=constraints)


def _copy_tuple_constructor_sequence(value: Sequence[object]) -> SymbolicList | None:
    copied = list(value)
    if all(_can_retain_tuple_constructor_item(item) for item in copied):
        return SymbolicList.from_const(copied)
    return None


def _can_retain_tuple_constructor_item(value: object) -> bool:
    if isinstance(value, tuple):
        tuple_items = cast("tuple[object, ...]", value)
        return all(_can_retain_tuple_constructor_item(item) for item in tuple_items)
    return isinstance(value, (SymbolicValue, int, bool, str))
