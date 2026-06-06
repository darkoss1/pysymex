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

from typing import TYPE_CHECKING, cast

from pysymex.models.builtins.core.helpers import resolve_heap_object
from pysymex.models.builtins.core.iterator_items import (
    concrete_iterable_items,
    contains_definitely_unhashable_item,
    iterator_exhaustion_side_effect,
)

from .shared import (
    FunctionModel,
    ModelResult,
    SymbolicNone,
    SymbolicValue,
    get_symbolic_set,
    replace_exact_set_value,
    set_length_expr,
    set_type_error_result,
    z3,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

"""Update symbolic set method models."""


class SetUpdateModel(FunctionModel):
    """Model for set.update(*others)."""

    name = "update"
    qualname = "set.update"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.update method."""
        if not args or kwargs:
            return set_type_error_result(self.name, state)
        s = get_symbolic_set(args[0]) if args else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if s is not None:
            exact_update = _exact_set_update(s, args[1:], state)
            if exact_update is not None:
                updated_values, iterator_side_effects = exact_update
                replace_exact_set_value(s, updated_values)
                side_effects.update(iterator_side_effects)
            else:
                z3_len = set_length_expr(s)
                if z3_len is not None:
                    new_len = z3.Int(f"set_len_{state.pc}")
                    constraints.append(new_len >= z3_len)
                    s.z3_int = new_len
            side_effects["set_mutation"] = {
                "operation": "update",
                "set_name": getattr(s, "_name", "set"),
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


def _exact_set_update(
    set_value: SymbolicValue,
    sources: list[StackValue],
    state: VMState,
) -> tuple[set[object], dict[str, object]] | None:
    concrete_value = set_value.value
    if not isinstance(concrete_value, set):
        return None

    concrete_set = _normalized_exact_set(cast("set[object]", concrete_value))
    source_items = _exact_set_source_items(sources, state)
    if source_items is None:
        return None
    update_items, iterator_side_effects = source_items

    updated_values: set[object] = set(concrete_set)
    updated_values.update(update_items)
    return updated_values, iterator_side_effects


def _exact_set_difference_update(
    set_value: SymbolicValue,
    sources: list[StackValue],
    state: VMState,
) -> tuple[set[object], dict[str, object]] | None:
    concrete_value = set_value.value
    if not isinstance(concrete_value, set):
        return None

    concrete_set = _normalized_exact_set(cast("set[object]", concrete_value))
    source_items = _exact_set_source_items(sources, state)
    if source_items is None:
        return None
    remove_items, iterator_side_effects = source_items

    remove_values = set(remove_items)
    updated_values = {item for item in concrete_set if item not in remove_values}
    return updated_values, iterator_side_effects


def _exact_set_intersection_update(
    set_value: SymbolicValue,
    sources: list[StackValue],
    state: VMState,
) -> tuple[set[object], dict[str, object]] | None:
    concrete_value = set_value.value
    if not isinstance(concrete_value, set):
        return None

    concrete_set = _normalized_exact_set(cast("set[object]", concrete_value))
    if not sources:
        return set(concrete_set), {}
    if len(sources) != 1:
        return None

    source_items = _exact_set_source_items(sources, state)
    if source_items is None:
        return None
    keep_items, iterator_side_effects = source_items

    keep_values = set(keep_items)
    updated_values = {item for item in concrete_set if item in keep_values}
    return updated_values, iterator_side_effects


def _exact_set_symmetric_difference_update(
    set_value: SymbolicValue,
    sources: list[StackValue],
    state: VMState,
) -> tuple[set[object], dict[str, object]] | None:
    concrete_value = set_value.value
    if not isinstance(concrete_value, set) or len(sources) != 1:
        return None

    concrete_set = _normalized_exact_set(cast("set[object]", concrete_value))
    source_items = _exact_set_source_items(sources, state)
    if source_items is None:
        return None
    toggle_items, iterator_side_effects = source_items

    toggle_values = set(toggle_items)
    updated_values = (concrete_set - toggle_values) | (toggle_values - concrete_set)
    return updated_values, iterator_side_effects


def _exact_set_source_items(
    sources: list[StackValue],
    state: VMState,
) -> tuple[list[object], dict[str, object]] | None:
    collected_items: list[object] = []
    iterator_side_effects: dict[str, object] = {}
    for source_arg in sources:
        source = resolve_heap_object(source_arg, state)
        direct_items = concrete_iterable_items(source, state)
        if direct_items is None or contains_definitely_unhashable_item(direct_items, state):
            return None
        try:
            for item in direct_items:
                collected_items.append(_exact_set_item_payload(item))
        except TypeError:
            return None

        side_effect = iterator_exhaustion_side_effect(source, state)
        if side_effect:
            if iterator_side_effects:
                return None
            iterator_side_effects = side_effect

    return collected_items, iterator_side_effects


def _normalized_exact_set(values: set[object]) -> set[object]:
    return {_exact_set_item_payload(item) for item in values}


def _exact_set_item_payload(item: object) -> object:
    if isinstance(item, SymbolicValue):
        concrete = item.value
        if concrete is not None:
            return concrete
    return item


class SetIntersectionUpdateModel(FunctionModel):
    """Model for set.intersection_update(*others)."""

    name = "intersection_update"
    qualname = "set.intersection_update"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.intersection_update method."""
        if not args or kwargs:
            return set_type_error_result(self.name, state)
        s = get_symbolic_set(args[0]) if args else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if s is not None:
            exact_update = _exact_set_intersection_update(s, args[1:], state)
            if exact_update is not None:
                updated_values, iterator_side_effects = exact_update
                replace_exact_set_value(s, updated_values)
                side_effects.update(iterator_side_effects)
            else:
                z3_len = set_length_expr(s)
                if z3_len is not None:
                    new_len = z3.Int(f"set_len_{state.pc}")
                    constraints.append(new_len <= z3_len)
                    constraints.append(new_len >= 0)
                    s.z3_int = new_len
            side_effects["set_mutation"] = {
                "operation": "intersection_update",
                "set_name": getattr(s, "_name", "set"),
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


class SetDifferenceUpdateModel(FunctionModel):
    """Model for set.difference_update(*others)."""

    name = "difference_update"
    qualname = "set.difference_update"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.difference_update method."""
        if not args or kwargs:
            return set_type_error_result(self.name, state)
        s = get_symbolic_set(args[0]) if args else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if s is not None:
            exact_update = _exact_set_difference_update(s, args[1:], state)
            if exact_update is not None:
                updated_values, iterator_side_effects = exact_update
                replace_exact_set_value(s, updated_values)
                side_effects.update(iterator_side_effects)
            else:
                z3_len = set_length_expr(s)
                if z3_len is not None:
                    new_len = z3.Int(f"set_len_{state.pc}")
                    constraints.append(new_len <= z3_len)
                    constraints.append(new_len >= 0)
                    s.z3_int = new_len
            side_effects["set_mutation"] = {
                "operation": "difference_update",
                "set_name": getattr(s, "_name", "set"),
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


class SetSymmetricDifferenceUpdateModel(FunctionModel):
    """Model for set.symmetric_difference_update(other)."""

    name = "symmetric_difference_update"
    qualname = "set.symmetric_difference_update"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.symmetric_difference_update method."""
        if len(args) != 2 or kwargs:
            return set_type_error_result(self.name, state)
        s = get_symbolic_set(args[0]) if args else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if s is not None:
            exact_update = _exact_set_symmetric_difference_update(s, args[1:], state)
            if exact_update is not None:
                updated_values, iterator_side_effects = exact_update
                replace_exact_set_value(s, updated_values)
                side_effects.update(iterator_side_effects)
            else:
                z3_len = set_length_expr(s)
                if z3_len is not None:
                    new_len = z3.Int(f"set_len_{state.pc}")
                    constraints.append(new_len >= 0)
                    s.z3_int = new_len
            side_effects["set_mutation"] = {
                "operation": "symmetric_difference_update",
                "set_name": getattr(s, "_name", "set"),
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )
