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

from .shared import (
    FunctionModel,
    ModelResult,
    SymbolicNone,
    SymbolicValue,
    dict_type_error_result,
    get_symbolic_dict,
    get_symbolic_string,
    symbolic_bool_result,
    symbolic_int_result,
    z3,
)

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.core.types.containers.dicts import SymbolicDict
    from pysymex.typing import StackValue

"""Dictionary access and query symbolic models."""


def _dict_key_arg(arg: object) -> SymbolicString | None:
    if isinstance(arg, str):
        return SymbolicString.from_const(arg)
    return get_symbolic_string(arg)


def _int_like_value(value: object) -> SymbolicValue | None:
    symbolic = SymbolicValue.from_const(value)
    if symbolic.affinity_type in {"int", "bool"}:
        return symbolic
    return None


def _conditional_get_value(
    d: SymbolicDict,
    raw_key: object,
    default_value: StackValue,
) -> SymbolicValue | None:
    value_conditions = d.concrete_value_conditions_for_key(raw_key)
    if value_conditions is None:
        return None

    default_symbolic = _int_like_value(default_value)
    if default_symbolic is None:
        return None

    result_expr = default_symbolic.z3_int
    for condition, value in reversed(value_conditions):
        value_symbolic = _int_like_value(value)
        if value_symbolic is None:
            return None
        result_expr = z3.If(condition, value_symbolic.z3_int, result_expr)

    return SymbolicValue(
        _name=f"{d.name}.get({getattr(raw_key, 'name', raw_key)!s})",
        z3_int=result_expr,
        is_int=Z3_TRUE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_str=Z3_FALSE,
        is_none=Z3_FALSE,
        affinity_type="int",
    )


class DictGetModel(FunctionModel):
    """Model for dict.get(key, default) - safe key access, never raises.
    Relationships:
    - If key exists: returns dict[key]
    - If key doesn't exist: returns default (None if not provided)
    - Never raises KeyError
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
            return dict_type_error_result(self.name, state)
        d = get_symbolic_dict(args[0], state) if args else None
        raw_key = args[1]
        key = _dict_key_arg(raw_key)
        default_value: StackValue = args[2] if len(args) > 2 else SymbolicNone()
        if d is not None:
            found, value = d.concrete_value_for_key(raw_key)
            if found:
                result_value = cast("StackValue", value) if value is not None else SymbolicNone()
                return ModelResult(value=result_value)
            presence = d.concrete_key_presence_condition(raw_key)
            if presence is not None and z3.is_false(z3.simplify(presence)):
                return ModelResult(value=default_value)

            conditional_value = _conditional_get_value(d, raw_key, default_value)
            if conditional_value is not None:
                return ModelResult(value=conditional_value)

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
                    )
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
        if d is not None and key is not None:
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
    - Otherwise: symbolic boolean based on key membership
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
        key = _dict_key_arg(args[1]) if len(args) > 1 else None
        if d is not None and key is not None:
            result = d.contains_key(key)
            constraints = [z3.Implies(d.z3_len == 0, z3.Not(result.z3_bool))]
            return ModelResult(value=result, constraints=constraints)
        result, constraints = symbolic_bool_result(f"dict_contains_{state.pc}")
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
        result, constraints = symbolic_int_result(f"dict_len_{state.pc}")
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
        result, constraints = symbolic_bool_result(f"dict_eq_{state.pc}")
        if d is not None and other is not None:
            constraints.append(z3.Implies(result.z3_bool, d.z3_len == other.z3_len))
            constraints.append(z3.Implies(d.z3_len != other.z3_len, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)
