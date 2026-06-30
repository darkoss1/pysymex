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

import z3

from pysymex._internal.core.constants import Z3_TRUE
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.core.types.containers.dict.selection import (
    NO_DEFAULT,
    conditional_retained_lookup_value,
)
from pysymex._internal.models.builtins.types.containers.dicts.shared import get_symbolic_dict
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

"""Symbolic dict pop-style mutation models."""


def _dict_key_arg(arg: object) -> SymbolicString | None:
    if isinstance(arg, str):
        return SymbolicString.from_const(arg)
    return SymbolicString.resolve(arg)


class DictPopModel(FunctionModel):
    """Model for dict.pop(key, [default]) - remove and return value.
    Behavior:
    - If key exists: remove key, return value, length decreases
    - If key doesn't exist and default given: return default
    - If key doesn't exist and no default: raise KeyError.
    """

    name = "pop"
    qualname = "dict.pop"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3} or kwargs:
            return ModelResult.method_type_error(f"dict.{self.name}", state)
        d = get_symbolic_dict(args[0]) if args else None
        raw_key = args[1] if len(args) > 1 else None
        key = _dict_key_arg(raw_key) if len(args) > 1 else None
        has_default = len(args) > 2
        result, constraint = SymbolicValue.symbolic(f"dict_pop_{state.pc}")
        constraints: list[z3.BoolRef] = [constraint]
        side_effects: dict[str, object] = {}
        if d is not None:
            if raw_key is not None:
                found, value = d.concrete_value_for_key(raw_key)
                if found:
                    old_len = d.z3_len
                    new_dict = d.__delitem__(raw_key)
                    side_effects["dict_mutation"] = {
                        "operation": "pop",
                        "original_dict": d,
                        "updated_dict": new_dict,
                        "dict_name": d.name,
                        "old_length": old_len,
                        "new_length": new_dict.z3_len,
                    }
                    result_value = (
                        cast("StackValue", value) if value is not None else SymbolicNoneType()
                    )
                    return ModelResult(value=result_value, side_effects=side_effects)
                presence = d.concrete_key_presence_condition(raw_key)
                if has_default and presence is not None and z3.is_false(simplify_expr(presence)):
                    return ModelResult(value=args[2])
                selected_value = conditional_retained_lookup_value(
                    d,
                    raw_key,
                    args[2] if has_default else NO_DEFAULT,
                    state=state,
                    name=f"{d.name}.pop({getattr(raw_key, 'name', raw_key)!s})",
                )
                if selected_value is not None:
                    key_present = (
                        presence
                        if presence is not None
                        else d.contains_key(key).z3_bool
                        if key is not None
                        else Z3_TRUE
                    )
                    old_len = d.z3_len
                    new_len = z3.If(key_present, old_len - 1, old_len)
                    new_dict = d.copy()
                    new_dict.z3_len = new_len
                    side_effects["dict_mutation"] = {
                        "operation": "pop",
                        "original_dict": d,
                        "updated_dict": new_dict,
                        "dict_name": d.name,
                        "old_length": old_len,
                        "new_length": new_len,
                    }
                    return ModelResult(value=selected_value, side_effects=side_effects)

            presence = d.concrete_key_presence_condition(raw_key) if raw_key is not None else None
            exception_condition: z3.BoolRef | None = None
            if presence is not None:
                exception_condition = z3.Not(presence)
            elif key is not None:
                exception_condition = z3.Not(d.contains_key(key).z3_bool)
            if not has_default and exception_condition is not None:
                side_effects["potential_exception"] = {
                    "type": "KeyError",
                    "message": "Key not found and no default provided",
                    "condition": exception_condition,
                }

            key_present = (
                presence
                if presence is not None
                else d.contains_key(key).z3_bool
                if key is not None
                else Z3_TRUE
            )
            old_len = d.z3_len
            new_len = z3.If(key_present, old_len - 1, old_len)
            new_dict = d.copy()
            new_dict.z3_len = new_len
            side_effects["dict_mutation"] = {
                "operation": "pop",
                "original_dict": d,
                "updated_dict": new_dict,
                "dict_name": d.name,
                "old_length": old_len,
                "new_length": new_len,
            }
        return ModelResult(
            value=result,
            constraints=constraints,
            side_effects=side_effects,
        )


class DictPopitemModel(FunctionModel):
    """Model for dict.popitem() - remove and return (key, value) pair.
    Raises: KeyError if dict is empty.
    Relationship: After popitem, len(dict) == old_len - 1.
    """

    name = "popitem"
    qualname = "dict.popitem"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(f"dict.{self.name}", state)
        d = get_symbolic_dict(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"dict_popitem_{state.pc}")
        constraints: list[z3.BoolRef] = [constraint, result.z3_len == 2]
        side_effects: dict[str, object] = {}
        if d is not None:
            old_len = d.z3_len
            constraints.append(old_len >= 1)
            side_effects["potential_exception"] = {
                "type": "KeyError",
                "message": "popitem(): dictionary is empty",
                "condition": old_len == 0,
            }
            new_dict = d.copy()
            new_len = old_len - 1
            new_dict.z3_len = new_len
            side_effects["dict_mutation"] = {
                "operation": "popitem",
                "original_dict": d,
                "updated_dict": new_dict,
                "dict_name": d.name,
                "old_length": old_len,
                "new_length": new_len,
            }
        return ModelResult(
            value=result,
            constraints=constraints,
            side_effects=side_effects,
        )
