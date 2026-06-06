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

from pysymex.core.constants import Z3_FALSE, Z3_TRUE
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.models.builtins.core.helpers import resolve_heap_object
from pysymex.models.builtins.core.iterator_items import (
    concrete_iterable_items,
    exact_dict_items_from_iterable,
    iterator_exhaustion_side_effect,
)

from ..shared import (
    FunctionModel,
    ModelResult,
    SymbolicDict,
    SymbolicNone,
    SymbolicValue,
    dict_type_error_result,
    get_symbolic_dict,
    get_symbolic_string,
    z3,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

"""Symbolic dict bulk and default-setting mutation models."""


def _dict_key_arg(arg: object) -> SymbolicString | None:
    if isinstance(arg, str):
        return SymbolicString.from_const(arg)
    return get_symbolic_string(arg)


def _concrete_dict_argument(arg: object) -> dict[str, object] | None:
    if not isinstance(arg, dict):
        return None
    updates: dict[str, object] = {}
    raw_updates = cast("dict[object, object]", arg)
    for key, value in raw_updates.items():
        if not isinstance(key, str):
            return None
        updates[key] = value
    return updates


class DictUpdateModel(FunctionModel):
    """Model for dict.update(other) - merge other into dict.
    Relationship: new_len >= old_len (may add new keys)
    """

    name = "update"
    qualname = "dict.update"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {1, 2}:
            return dict_type_error_result(self.name, state)
        d = get_symbolic_dict(args[0], state) if args else None
        other_arg = args[1] if len(args) > 1 else None
        other = get_symbolic_dict(other_arg, state) if len(args) > 1 else None
        constraints: list[z3.BoolRef] = []
        side_effects: dict[str, object] = {}
        if d is not None:
            old_length = d.z3_len
            updated_dict: SymbolicDict = d
            if other is not None:
                updated_dict, update_constraint = updated_dict.update(other)
                constraints.append(update_constraint)
            elif other_arg is not None:
                source = resolve_heap_object(other_arg, state)
                concrete_other = _concrete_dict_argument(source)
                if concrete_other is not None:
                    updated_dict, update_constraint = updated_dict.update(concrete_other)
                    constraints.append(update_constraint)
                else:
                    direct_items = concrete_iterable_items(source, state)
                    exact_items = (
                        exact_dict_items_from_iterable(direct_items, state)
                        if direct_items is not None
                        else None
                    )
                    if exact_items is not None:
                        updated_dict, update_constraint = updated_dict.update(exact_items)
                        constraints.append(update_constraint)
                        iterator_side_effect = iterator_exhaustion_side_effect(source, state)
                        if iterator_side_effect:
                            side_effects.update(iterator_side_effect)
                    else:
                        side_effects["dict_mutation"] = {
                            "operation": "update",
                            "dict_name": d.name,
                            "old_length": d.z3_len,
                            "length_may_increase": True,
                        }
            if kwargs:
                keyword_updates: dict[str, object] = {key: value for key, value in kwargs.items()}
                updated_dict, keyword_constraint = updated_dict.update(keyword_updates)
                constraints.append(keyword_constraint)

            if updated_dict is not d:
                side_effects["dict_mutation"] = {
                    "operation": "update",
                    "original_dict": d,
                    "updated_dict": updated_dict,
                    "dict_name": d.name,
                    "old_length": old_length,
                    "new_length": updated_dict.z3_len,
                }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


class DictClearModel(FunctionModel):
    """Model for dict.clear() - remove all items.
    Relationship: After clear, len(dict) == 0
    """

    name = "clear"
    qualname = "dict.clear"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return dict_type_error_result(self.name, state)
        d = get_symbolic_dict(args[0], state) if args else None
        side_effects: dict[str, object] = {}
        if d is not None:
            updated_dict = d.clear()
            side_effects["dict_mutation"] = {
                "operation": "clear",
                "original_dict": d,
                "updated_dict": updated_dict,
                "dict_name": d.name,
                "old_length": d.z3_len,
                "new_length": updated_dict.z3_len,
            }
        return ModelResult(
            value=SymbolicNone(),
            side_effects=side_effects,
        )


class DictSetdefaultModel(FunctionModel):
    """Model for dict.setdefault(key, default) - get or set key.
    Behavior:
    - If key exists: return dict[key]
    - If key doesn't exist: dict[key] = default, return default
    Relationship: new_len is either old_len (key existed) or old_len + 1
    """

    name = "setdefault"
    qualname = "dict.setdefault"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3} or kwargs:
            return dict_type_error_result(self.name, state)
        d = get_symbolic_dict(args[0], state) if args else None
        key = _dict_key_arg(args[1]) if len(args) > 1 else None
        default_value: StackValue = args[2] if len(args) > 2 else SymbolicNone()
        result, constraint = SymbolicValue.symbolic(f"dict_setdefault_{state.pc}")
        constraints: list[z3.BoolRef] = [constraint]
        side_effects: dict[str, object] = {}
        if d is not None and key is not None:
            found, retained_value = d.concrete_value_for_key(key)
            if found:
                result_value = (
                    cast("StackValue", retained_value)
                    if retained_value is not None
                    else SymbolicNone()
                )
                return ModelResult(value=result_value)

            presence = d.concrete_key_presence_condition(key)
            if presence is not None and z3.is_false(z3.simplify(presence)):
                updated_dict = d.__setitem__(key, default_value)
                side_effects["dict_mutation"] = {
                    "operation": "setdefault",
                    "original_dict": d,
                    "updated_dict": updated_dict,
                }
                return ModelResult(value=default_value, side_effects=side_effects)

            stored_value, presence_check = d.__getitem__(key)
            default_symbolic = SymbolicValue.from_const(default_value)
            if default_symbolic.affinity_type in {"int", "bool"}:
                result = SymbolicValue(
                    _name=f"{d.name}.setdefault({key.name})",
                    z3_int=z3.If(presence_check, stored_value.z3_int, default_symbolic.z3_int),
                    is_int=Z3_TRUE,
                    z3_bool=Z3_FALSE,
                    is_bool=Z3_FALSE,
                    is_str=Z3_FALSE,
                    is_none=Z3_FALSE,
                    affinity_type="int",
                )
                constraints = []
            inserted_dict = d.__setitem__(key, default_value)
            updated_dict = inserted_dict.conditional_merge(d, z3.Not(presence_check))
            if isinstance(updated_dict, SymbolicDict):
                side_effects["dict_mutation"] = {
                    "operation": "setdefault",
                    "original_dict": d,
                    "updated_dict": updated_dict,
                }
        return ModelResult(
            value=result,
            constraints=constraints,
            side_effects=side_effects,
        )


__all__ = ["DictClearModel", "DictSetdefaultModel", "DictUpdateModel"]
