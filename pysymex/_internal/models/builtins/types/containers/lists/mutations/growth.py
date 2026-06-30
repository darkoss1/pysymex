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
    insert_retained_sequence_item,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

"""Length-increasing symbolic list method models."""


class ListAppendModel(FunctionModel):
    """Model for list.append(x) - increases list length by 1.
    Relationship: After append, len(list) == old_len + 1
    Side effect: Updates the list's symbolic length constraint.
    """

    name = "append"
    qualname = "list.append"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error("list.append", state)
        lst = SymbolicList.resolve(args[0], state) if args else None
        element = args[1] if len(args) > 1 else None
        side_effects: dict[str, object] = {}
        if lst is not None:
            new_list = lst.append(element)
            side_effects["list_mutation"] = {
                "operation": "append",
                "original_list": lst,
                "updated_list": new_list,
            }
        else:
            from pysymex._internal.logging.root import get_logger

            get_logger("pysymex").debug(
                "ListAppendModel failed to find list in %s",
                args[0] if args else "None",
            )
        return ModelResult(
            value=SymbolicNoneType(),
            side_effects=side_effects,
        )


class ListExtendModel(FunctionModel):
    """Model for list.extend(iterable) - increases length by len(iterable).
    Relationship: len(list) >= old_len (extends by >= 0 elements).
    """

    name = "extend"
    qualname = "list.extend"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error("list.extend", state)
        lst = SymbolicList.resolve(args[0], state) if args else None
        extension = SymbolicList.resolve(args[1], state) if len(args) > 1 else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if lst is not None:
            if extension is not None:
                new_list = concat_concrete_backed_sequences(lst, extension)
                if new_list is None:
                    new_len = z3.Int(f"extend_len_{state.pc}_{state.path_id}")
                    constraints.append(new_len == lst.z3_len + extension.z3_len)
                    new_list = lst.copy()
                    new_list.z3_len = new_len
            else:
                source = SymbolicObject.resolve(args[1], state)
                direct_items = IterationSources.iterable_items(source, state)
                if direct_items is not None:
                    extension_items: list[object] = list(direct_items)
                    new_list = lst.extend(extension_items)
                    iterator_side_effect = iterator_exhaustion_side_effect(source, state)
                    if iterator_side_effect:
                        side_effects.update(iterator_side_effect)
                else:
                    new_list = lst.copy()

            side_effects["list_mutation"] = {
                "operation": "extend",
                "original_list": lst,
                "updated_list": new_list,
            }
        return ModelResult(
            value=SymbolicNoneType(),
            constraints=constraints,
            side_effects=side_effects,
        )


class ListInsertModel(FunctionModel):
    """Model for list.insert(i, x) - increases list length by 1.
    Relationship: After insert, len(list) == old_len + 1
    Note: Index i can be any value (negative, > len are valid).
    """

    name = "insert"
    qualname = "list.insert"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 3 or kwargs:
            return ModelResult.method_type_error("list.insert", state)
        lst = SymbolicList.resolve(args[0], state) if args else None
        side_effects: dict[str, object] = {}
        if lst is not None:
            new_list = insert_retained_sequence_item(
                lst,
                args[1],
                args[2],
                state.path_constraints.to_list(),
            )
            if new_list is None:
                new_list = lst.copy()
                new_list.z3_len = lst.z3_len + 1

            side_effects["list_mutation"] = {
                "operation": "insert",
                "original_list": lst,
                "updated_list": new_list,
            }
        return ModelResult(
            value=SymbolicNoneType(),
            side_effects=side_effects,
        )
