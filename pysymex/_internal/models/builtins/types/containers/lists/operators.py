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

import z3

from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.models.builtins.iteration.consumption import iterator_exhaustion_side_effect
from pysymex._internal.models.builtins.iteration.sources import IterationSources
from pysymex._internal.core.types.containers.sequence_precision import (
    concat_concrete_backed_sequences,
    concrete_repeat_count,
    repeat_concrete_backed_sequence,
    repeat_count_expr,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

"""Operator symbolic list models."""


class ListAddModel(FunctionModel):
    """Model for list.__add__(other) - concatenation."""

    name = "__add__"
    qualname = "list.__add__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply list.__add__ method."""
        lst = SymbolicList.resolve(args[0], state) if args else None
        other = SymbolicList.resolve(args[1], state) if len(args) > 1 else None
        if lst is not None and other is not None:
            concatenated = concat_concrete_backed_sequences(lst, other)
            if concatenated is not None:
                return ModelResult(value=concatenated)
        result, constraint = SymbolicList.symbolic(f"list_add_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        if lst is not None and other is not None:
            constraints.append(result.z3_len == lst.z3_len + other.z3_len)
        elif lst is not None:
            constraints.append(result.z3_len >= lst.z3_len)
        return ModelResult(value=result, constraints=constraints)


class ListMulModel(FunctionModel):
    """Model for list.__mul__(n) - repetition."""

    name = "__mul__"
    qualname = "list.__mul__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply list.__mul__ method."""
        lst = SymbolicList.resolve(args[0], state) if args else None
        n = args[1] if len(args) > 1 else None
        if lst is not None and n is not None:
            count = concrete_repeat_count(n)
            if count is not None:
                repeated = repeat_concrete_backed_sequence(lst, count)
                if repeated is not None:
                    return ModelResult(value=repeated)
        result, constraint = SymbolicList.symbolic(f"list_mul_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        if lst is not None and n is not None:
            n_val = repeat_count_expr(n)
            if n_val is not None:
                constraints.append(
                    z3.If(
                        n_val > 0,
                        result.z3_len == lst.z3_len * n_val,
                        result.z3_len == 0,
                    ),
                )
        return ModelResult(value=result, constraints=constraints)


class ListIaddModel(FunctionModel):
    """Model for list.__iadd__(other) - in-place extend via +=."""

    name = "__iadd__"
    qualname = "list.__iadd__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply list.__iadd__ method."""
        lst = SymbolicList.resolve(args[0], state) if args else None
        other = SymbolicList.resolve(args[1], state) if len(args) > 1 else None
        source = SymbolicObject.resolve(args[1], state) if len(args) > 1 else None
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        side_effects: dict[str, object] = {}
        if lst is not None:
            new_list = concat_concrete_backed_sequences(lst, other) if other is not None else None
            if new_list is None:
                direct_items = (
                    IterationSources.iterable_items(source, state) if source is not None else None
                )
                if direct_items is not None:
                    extension_items: list[object] = list(direct_items)
                    new_list = lst.extend(extension_items)
                    iterator_side_effect = iterator_exhaustion_side_effect(source, state)
                    if iterator_side_effect:
                        side_effects.update(iterator_side_effect)
                else:
                    new_list = lst.copy()
                    new_len = z3.Int(f"list_len_{state.pc}_{state.path_id}")
                    if other is not None:
                        constraints.append(new_len == lst.z3_len + other.z3_len)
                    else:
                        constraints.append(new_len >= lst.z3_len)
                    constraints.append(new_len >= 0)
                    new_list.z3_len = new_len
            side_effects["list_mutation"] = {
                "operation": "iadd",
                "original_list": lst,
                "updated_list": new_list,
            }
        return ModelResult(
            value=args[0] if args else SymbolicNoneType(),
            constraints=constraints,
            side_effects=side_effects,
        )


class ListImulModel(FunctionModel):
    """Model for list.__imul__(n) - in-place repetition via *=."""

    name = "__imul__"
    qualname = "list.__imul__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply list.__imul__ method."""
        lst = SymbolicList.resolve(args[0], state) if args else None
        n = args[1] if len(args) > 1 else None
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        side_effects: dict[str, object] = {}
        if lst is not None:
            count = concrete_repeat_count(n) if n is not None else None
            new_list = repeat_concrete_backed_sequence(lst, count) if count is not None else None
            if new_list is None:
                new_list = lst.copy()
                new_len = z3.Int(f"list_len_{state.pc}_{state.path_id}")
                n_val = repeat_count_expr(n) if n is not None else None
                if n_val is not None:
                    constraints.append(
                        z3.If(
                            n_val > 0,
                            new_len == lst.z3_len * n_val,
                            new_len == 0,
                        ),
                    )
                else:
                    constraints.append(new_len >= 0)
                new_list.z3_len = new_len
            if count is not None and count < 0:
                constraints.append(new_list.z3_len == 0)
            side_effects["list_mutation"] = {
                "operation": "imul",
                "original_list": lst,
                "updated_list": new_list,
            }
        return ModelResult(
            value=args[0] if args else SymbolicNoneType(),
            constraints=constraints,
            side_effects=side_effects,
        )
