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

from pysymex.models.builtins.core.helpers import resolve_heap_object
from pysymex.models.builtins.core.iterator_items import (
    concrete_iterable_items,
    exact_dict_items_from_iterable,
    iterator_exhaustion_side_effect,
)

from .shared import (
    FunctionModel,
    ModelResult,
    SymbolicDict,
    SymbolicNone,
    get_symbolic_dict,
    z3,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

"""Dictionary merge operator symbolic models."""


def exact_dict_ior_items(value: StackValue, state: VMState) -> dict[object, object] | None:
    """Return exact items when ``dict |= value`` can consume iterable pairs."""
    source = resolve_heap_object(value, state)
    direct_items = concrete_iterable_items(source, state)
    if direct_items is None:
        return None
    return exact_dict_items_from_iterable(direct_items, state)


class DictOrModel(FunctionModel):
    """Model for dict.__or__(other) - merge operator (Python 3.9+)."""

    name = "__or__"
    qualname = "dict.__or__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = get_symbolic_dict(args[0], state) if args else None
        other = get_symbolic_dict(args[1], state) if len(args) > 1 else None
        result, constraint = SymbolicDict.symbolic(f"dict_or_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        if d is not None and other is not None:
            merged, merge_constraint = d.update(other)
            return ModelResult(value=merged, constraints=[merge_constraint])
        elif d is not None:
            constraints.append(result.z3_len >= d.z3_len)
        return ModelResult(value=result, constraints=constraints)


class DictIorModel(FunctionModel):
    """Model for dict.__ior__(other) - in-place merge via |=."""

    name = "__ior__"
    qualname = "dict.__ior__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = get_symbolic_dict(args[0], state) if args else None
        other = get_symbolic_dict(args[1], state) if len(args) > 1 else None
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        side_effects: dict[str, object] = {}
        result: StackValue = args[0] if args else SymbolicNone()
        if d is not None and other is not None:
            updated_dict, merge_constraint = d.update(other)
            constraints.append(merge_constraint)
            result = updated_dict
            side_effects["dict_mutation"] = {
                "operation": "ior",
                "original_dict": d,
                "updated_dict": updated_dict,
                "dict_name": getattr(d, "name", "dict"),
            }
        elif d is not None and len(args) > 1:
            exact_items = exact_dict_ior_items(args[1], state)
            if exact_items is not None:
                updated_dict, merge_constraint = d.update(exact_items)
                constraints.append(merge_constraint)
                result = updated_dict
                side_effects["dict_mutation"] = {
                    "operation": "ior",
                    "original_dict": d,
                    "updated_dict": updated_dict,
                    "dict_name": getattr(d, "name", "dict"),
                }
                iterator_side_effect = iterator_exhaustion_side_effect(args[1], state)
                if iterator_side_effect:
                    side_effects.update(iterator_side_effect)
        return ModelResult(
            value=result,
            constraints=constraints,
            side_effects=side_effects,
        )
