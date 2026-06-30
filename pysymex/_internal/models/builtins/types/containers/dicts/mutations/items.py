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

from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.dict.keys import symbolic_storage_key
from pysymex._internal.models.builtins.types.containers.dicts.shared import get_symbolic_dict
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult, SideEffects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.types.containers.dicts import SymbolicDict
    from pysymex._internal.typing.protocols import StackValue

"""Symbolic dict item assignment and deletion models."""


class DictSetitemModel(FunctionModel):
    """Model for dict[key] = value - adds or updates key.
    Relationship:
    - If key was new: length increases by 1
    - If key existed: length unchanged.
    """

    name = "__setitem__"
    qualname = "dict.__setitem__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 3 or kwargs:
            return ModelResult.method_type_error("dict.__setitem__", state)
        d = get_symbolic_dict(args[0], state) if args else None
        side_effects: dict[str, object] = {}
        if d is not None:
            new_dict = d.__setitem__(args[1], args[2])
            side_effects["dict_mutation"] = {
                "operation": "setitem",
                "original_dict": d,
                "updated_dict": new_dict,
            }
        return ModelResult(
            value=SymbolicNoneType(),
            side_effects=side_effects,
        )


class DictDelitemModel(FunctionModel):
    """Model for del dict[key] - may raise KeyError.
    Relationship:
    - If key exists: length decreases by 1
    - If key doesn't exist: raises KeyError.
    """

    name = "__delitem__"
    qualname = "dict.__delitem__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error("dict.__delitem__", state)
        d = get_symbolic_dict(args[0], state) if args else None
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        side_effects: dict[str, object] = {}
        if d is not None:
            key = args[1]
            presence_condition = _key_presence_condition(d, key)
            missing_condition = simplify_expr(z3.Not(presence_condition))
            if _path_implies(state, missing_condition):
                return ModelResult.none(
                    side_effects=SideEffects.from_native_exception(
                        "dict.__delitem__",
                        KeyError(key),
                    ),
                )

            if not _path_refutes(state, missing_condition):
                side_effects["potential_exception"] = {
                    "type": "KeyError",
                    "message": "Key not found for deletion",
                    "condition": missing_condition,
                }
                constraints.append(presence_condition)

            new_dict = d.__delitem__(key)
            side_effects["dict_mutation"] = {
                "operation": "delitem",
                "original_dict": d,
                "updated_dict": new_dict,
            }
        return ModelResult(
            value=SymbolicNoneType(),
            constraints=constraints,
            side_effects=side_effects,
        )


def _key_presence_condition(d: SymbolicDict, key: object) -> z3.BoolRef:
    retained_presence = d.concrete_key_presence_condition(key)
    if retained_presence is not None:
        return retained_presence
    storage_key = symbolic_storage_key(key)
    return simplify_expr(cast("z3.BoolRef", z3.Select(d.known_keys, storage_key.z3_str)))


def _path_refutes(state: VMState, condition: z3.BoolRef) -> bool:
    simplified = simplify_expr(condition)
    if z3.is_false(simplified):
        return True
    if z3.is_true(simplified):
        return False
    solver = z3.Solver()
    solver.add(*state.path_constraints.to_list(), simplified)
    return solver.check() == z3.unsat


def _path_implies(state: VMState, condition: z3.BoolRef) -> bool:
    simplified = simplify_expr(condition)
    if z3.is_true(simplified):
        return True
    if z3.is_false(simplified):
        return False
    solver = z3.Solver()
    solver.add(*state.path_constraints.to_list(), z3.Not(simplified))
    return solver.check() == z3.unsat
