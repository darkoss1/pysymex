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

from pysymex.core.constants import Z3_TRUE

from ..shared import (
    FunctionModel,
    ModelResult,
    SymbolicNone,
    SymbolicValue,
    get_symbolic_dict,
    get_symbolic_string,
    z3,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

"""Symbolic dict item assignment and deletion models."""


class DictSetitemModel(FunctionModel):
    """Model for dict[key] = value - adds or updates key.
    Relationship:
    - If key was new: length increases by 1
    - If key existed: length unchanged
    """

    name = "__setitem__"
    qualname = "dict.__setitem__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = get_symbolic_dict(args[0], state) if args else None
        key_arg = args[1] if len(args) > 1 else None
        value_arg = args[2] if len(args) > 2 else None
        key = get_symbolic_string(key_arg) if key_arg is not None else None
        value = (
            value_arg
            if isinstance(value_arg, SymbolicValue)
            else SymbolicValue.from_const(value_arg)
        )
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef] = []
        if d is not None and key is not None:
            new_len = z3.Int(f"dict_len_{state.pc}_{state.path_id}")
            exists = d.contains_key(key)
            constraints.append(z3.If(exists.z3_bool, new_len == d.z3_len, new_len == d.z3_len + 1))

            new_dict = d.copy()
            new_dict.z3_len = new_len
            if value_arg is not None:
                new_dict.z3_array = z3.Store(d.z3_array, key.z3_str, value.z3_int)
            new_dict.known_keys = z3.Store(d.known_keys, key.z3_str, Z3_TRUE)

            side_effects["dict_mutation"] = {
                "operation": "setitem",
                "original_dict": d,
                "updated_dict": new_dict,
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints if d is not None else [],
            side_effects=side_effects,
        )


class DictDelitemModel(FunctionModel):
    """Model for del dict[key] - may raise KeyError.
    Relationship:
    - If key exists: length decreases by 1
    - If key doesn't exist: raises KeyError
    """

    name = "__delitem__"
    qualname = "dict.__delitem__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = get_symbolic_dict(args[0], state) if args else None
        key = get_symbolic_string(args[1]) if len(args) > 1 else None
        constraints: list[z3.BoolRef] = []
        side_effects: dict[str, object] = {}
        if d is not None:
            constraints.append(d.z3_len >= 1)
            if key is not None:
                side_effects["potential_exception"] = {
                    "type": "KeyError",
                    "message": "Key not found for deletion",
                    "condition": z3.Not(d.contains_key(key).z3_bool),
                }

            new_dict = d.copy()
            new_dict.z3_len = d.z3_len - 1

            side_effects["dict_mutation"] = {
                "operation": "delitem",
                "original_dict": d,
                "updated_dict": new_dict,
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


__all__ = ["DictDelitemModel", "DictSetitemModel"]
