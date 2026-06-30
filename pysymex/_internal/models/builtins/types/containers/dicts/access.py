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

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.state.record import StateConstraints
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.core.types.containers.dict.selection import (
    NO_DEFAULT,
    conditional_retained_lookup_value,
)
from pysymex._internal.guards import RuntimeObjectGuards
from pysymex._internal.core.solver.feasibility_context import path_may_be_feasible
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

from .shared import (
    get_symbolic_dict,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.types.containers.dicts import SymbolicDict
    from pysymex._internal.typing.protocols import StackValue

"""Dictionary access and query symbolic models."""

_STRING_LIST_VALUE_TYPE = "list[str]"


def _dict_key_arg(arg: object) -> SymbolicString | None:
    if isinstance(arg, str):
        return SymbolicString.from_const(arg)
    return SymbolicString.resolve(arg)


def _bool_value(name: str, condition: z3.BoolRef) -> SymbolicValue:
    return SymbolicValue(
        _name=name,
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=simplify_expr(condition),
        is_bool=Z3_TRUE,
        is_str=Z3_FALSE,
        is_none=Z3_FALSE,
        affinity_type="bool",
    )


def _symbolic_string_list_value(
    d: SymbolicDict,
    key: SymbolicString,
    state: VMState,
) -> tuple[SymbolicList, list[z3.BoolRef]]:
    item, constraint = SymbolicString.symbolic(f"{d.name}.get({key.name})[0]_{state.pc}")
    return SymbolicList.from_const([item]), [constraint]


def _default_guarantees_non_empty_list(value: StackValue, state: VMState) -> bool:
    resolved: object = SymbolicObject.resolve(value, state)
    if RuntimeObjectGuards.list(resolved):
        return bool(resolved)
    if isinstance(resolved, SymbolicList):
        concrete_items = resolved.concrete_items
        if concrete_items is not None:
            return bool(concrete_items)
        return z3.is_true(simplify_expr(resolved.z3_len > 0))
    return False


def _path_refutes(state: VMState, condition: z3.BoolRef) -> bool:
    simplified = simplify_expr(condition)
    if z3.is_false(simplified):
        return True
    if z3.is_true(simplified):
        return False
    constraints = [*state.path_constraints.to_list(), simplified]
    return not path_may_be_feasible(
        constraints,
        known_sat_prefix_len=StateConstraints.known_sat_prefix_len(state),
    )


def _path_implies(state: VMState, condition: z3.BoolRef) -> bool:
    simplified = simplify_expr(condition)
    if z3.is_true(simplified):
        return True
    if z3.is_false(simplified):
        return False
    return _path_refutes(state, z3.Not(simplified))


def _path_proved_retained_get_value(
    d: SymbolicDict,
    raw_key: object,
    default_value: StackValue,
    state: VMState,
) -> tuple[bool, StackValue]:
    value_conditions = d.concrete_value_conditions_for_key(raw_key)
    if value_conditions is None:
        return False, default_value

    possible_matches: list[tuple[z3.BoolRef, object]] = []
    for condition, value in value_conditions:
        if not _path_refutes(state, condition):
            possible_matches.append((condition, value))
    if not possible_matches:
        return True, default_value

    presence = simplify_expr(z3.Or(*(condition for condition, _value in value_conditions)))
    if not _path_implies(state, presence):
        return False, default_value
    if len(possible_matches) != 1:
        return False, default_value

    retained_value = possible_matches[0][1]
    result_value = (
        cast("StackValue", retained_value) if retained_value is not None else SymbolicNoneType()
    )
    return True, result_value


def _path_proved_retained_getitem_value(
    d: SymbolicDict,
    raw_key: object,
    state: VMState,
) -> tuple[bool, StackValue | None]:
    value_conditions = d.concrete_value_conditions_for_key(raw_key)
    if value_conditions is None:
        return False, None

    possible_matches: list[tuple[z3.BoolRef, object]] = []
    for condition, value in value_conditions:
        if not _path_refutes(state, condition):
            possible_matches.append((condition, value))
    if not possible_matches:
        return False, None

    presence = simplify_expr(z3.Or(*(condition for condition, _value in value_conditions)))
    if not _path_implies(state, presence):
        return False, None
    if len(possible_matches) == 1:
        retained_value = possible_matches[0][1]
        result_value = (
            cast("StackValue", retained_value) if retained_value is not None else SymbolicNoneType()
        )
        return True, result_value

    conditional_value = conditional_retained_lookup_value(
        d,
        raw_key,
        NO_DEFAULT,
        state=state,
        name=f"{d.name}[{getattr(raw_key, 'name', raw_key)!s}]",
    )
    if conditional_value is None:
        return False, None
    return True, conditional_value


class DictGetModel(FunctionModel):
    """Model for dict.get(key, default) - safe key access, never raises.
    Relationships:
    - If key exists: returns dict[key]
    - If key doesn't exist: returns default (None if not provided)
    - Never raises KeyError.
    """

    name = "get"
    qualname = "dict.get"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3} or kwargs:
            return ModelResult.method_type_error(f"dict.{self.name}", state)
        d = get_symbolic_dict(args[0], state) if args else None
        raw_key = args[1]
        key = _dict_key_arg(raw_key)
        default_value: StackValue = args[2] if len(args) > 2 else SymbolicNoneType()
        if d is not None:
            found, value = d.concrete_value_for_key(raw_key)
            if found:
                result_value = (
                    cast("StackValue", value) if value is not None else SymbolicNoneType()
                )
                return ModelResult(value=result_value)
            presence = d.concrete_key_presence_condition(raw_key)
            if presence is not None and z3.is_false(simplify_expr(presence)):
                return ModelResult(value=default_value)
            path_proved, path_proved_value = _path_proved_retained_get_value(
                d,
                raw_key,
                default_value,
                state,
            )
            if path_proved:
                return ModelResult(value=path_proved_value)
            value_conditions = d.concrete_value_conditions_for_key(raw_key)
            if value_conditions is not None and len(value_conditions) == 1:
                condition, retained_value = value_conditions[0]
                if z3.is_true(simplify_expr(condition)):
                    result_value = (
                        cast("StackValue", retained_value)
                        if retained_value is not None
                        else SymbolicNoneType()
                    )
                    return ModelResult(value=result_value)

            conditional_value = conditional_retained_lookup_value(
                d,
                raw_key,
                default_value,
                state=state,
                name=f"{d.name}.get({getattr(raw_key, 'name', raw_key)!s})",
            )
            if conditional_value is not None:
                return ModelResult(value=conditional_value)

            if (
                getattr(d, "_value_type", None) == _STRING_LIST_VALUE_TYPE
                and key is not None
                and _default_guarantees_non_empty_list(default_value, state)
            ):
                result_value, constraints = _symbolic_string_list_value(d, key, state)
                return ModelResult(value=result_value, constraints=constraints)

        if d is not None and key is not None:
            stored_value, presence_check = d.__getitem__(key)
            default_symbolic = SymbolicValue.from_const(default_value)
            if default_symbolic.affinity_type in {"int", "bool"}:
                return ModelResult(
                    value=SymbolicValue(
                        _name=f"{d.name}.get({key.name})",
                        z3_int=z3.If(
                            presence_check,
                            stored_value.z3_int,
                            default_symbolic.z3_int,
                        ),
                        is_int=Z3_TRUE,
                        z3_bool=Z3_FALSE,
                        is_bool=Z3_FALSE,
                        is_str=Z3_FALSE,
                        is_none=Z3_FALSE,
                        affinity_type="int",
                    ),
                )
        result, constraint = SymbolicValue.symbolic(f"dict_get_{state.pc}_{state.path_id}")
        constraints = [constraint]
        if d is not None and key is not None:
            d.contains_key(key)
        return ModelResult(value=result, constraints=constraints)


class DictGetitemModel(FunctionModel):
    """Model for dict[key] - may raise KeyError.
    Bug detection: Can find cases where key might not exist.
    """

    name = "__getitem__"
    qualname = "dict.__getitem__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = get_symbolic_dict(args[0], state) if args else None
        key = _dict_key_arg(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicValue.symbolic(f"dict_getitem_{state.pc}_{state.path_id}")
        constraints: list[z3.BoolRef] = [constraint]
        side_effects: dict[str, object] = {}
        if d is not None:
            found, retained_value = d.concrete_value_for_key(args[1])
            if found:
                result_value = (
                    cast("StackValue", retained_value)
                    if retained_value is not None
                    else SymbolicNoneType()
                )
                return ModelResult(value=result_value)
            path_proved, path_value = _path_proved_retained_getitem_value(
                d,
                args[1],
                state,
            )
            if path_proved:
                return ModelResult(value=path_value)
        if d is not None and key is not None:
            if getattr(d, "_value_type", None) == _STRING_LIST_VALUE_TYPE:
                result_value, constraints = _symbolic_string_list_value(d, key, state)
                return ModelResult(
                    value=result_value,
                    constraints=constraints,
                    side_effects={
                        "potential_exception": {
                            "type": "KeyError",
                            "message": "Key not found in dictionary",
                            "condition": z3.Not(d.contains_key(key).z3_bool),
                        },
                    },
                )
            side_effects["potential_exception"] = {
                "type": "KeyError",
                "message": "Key not found in dictionary",
                "condition": z3.Not(d.contains_key(key).z3_bool),
            }
        return ModelResult(
            value=result,
            constraints=constraints,
            side_effects=side_effects,
        )


class DictContainsModel(FunctionModel):
    """Model for 'key in dict' operation.
    Relationship:
    - If dict is empty: result is False
    - Otherwise: symbolic boolean based on key membership.
    """

    name = "__contains__"
    qualname = "dict.__contains__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = get_symbolic_dict(args[0], state) if args else None
        raw_key = args[1] if len(args) > 1 else None
        key = _dict_key_arg(args[1]) if len(args) > 1 else None
        if d is not None:
            concrete_presence = d.concrete_key_presence_condition(raw_key)
            if concrete_presence is not None:
                return ModelResult(
                    value=_bool_value(
                        f"{getattr(raw_key, 'name', raw_key)!s} in {d.name}",
                        concrete_presence,
                    ),
                )
        if d is not None and key is not None:
            result = d.contains_key(key)
            constraints = [z3.Implies(d.z3_len == 0, z3.Not(result.z3_bool))]
            return ModelResult(value=result, constraints=constraints)
        result, constraints = ModelResult.symbolic_bool(f"dict_contains_{state.pc}")
        return ModelResult(
            value=result,
            constraints=constraints,
        )


class DictLenModel(FunctionModel):
    """Model for len(dict)."""

    name = "__len__"
    qualname = "dict.__len__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = get_symbolic_dict(args[0], state) if args else None
        if d is not None:
            result = SymbolicValue(
                _name=f"len({d.name})",
                z3_int=d.z3_len,
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
            )
            return ModelResult(value=result, constraints=[])
        result, constraints = ModelResult.symbolic_int(f"dict_len_{state.pc}")
        constraints.append(result.z3_int >= 0)
        return ModelResult(
            value=result,
            constraints=constraints,
        )


class DictEqModel(FunctionModel):
    """Model for dict.__eq__(other)."""

    name = "__eq__"
    qualname = "dict.__eq__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = get_symbolic_dict(args[0], state) if args else None
        other = get_symbolic_dict(args[1], state) if len(args) > 1 else None
        result, constraints = ModelResult.symbolic_bool(f"dict_eq_{state.pc}")
        if d is not None and other is not None:
            constraints.append(z3.Implies(result.z3_bool, d.z3_len == other.z3_len))
            constraints.append(z3.Implies(d.z3_len != other.z3_len, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)
