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

"""Membership-changing symbolic set method models."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.set_retention import (
    replace_exact_set_value,
    set_absence_condition,
    set_length_expr,
)
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.types.containers.sets.shared import get_symbolic_set
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class SetAddModel(FunctionModel):
    """Model for set.add(elem)."""

    name = "add"
    qualname = "set.add"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.add method."""
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error(f"set.{self.name}", state)
        s = get_symbolic_set(args[0]) if args else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if s is not None:
            z3_len = set_length_expr(s)
            exact_item = _exact_hashable_item(args[1] if len(args) > 1 else None)
            concrete_set = _exact_set_payload(s)
            if concrete_set is not None and exact_item is not _UNKNOWN_SET_ITEM:
                old_length = z3_len
                updated_set = set(concrete_set)
                updated_set.add(exact_item)
                replace_exact_set_value(s, updated_set)
                side_effects["set_mutation"] = {
                    "operation": "add",
                    "set_name": getattr(s, "_name", "set"),
                    "old_length": old_length,
                    "new_length": set_length_expr(s),
                    "length_may_increase": True,
                }
                return ModelResult(
                    value=SymbolicNoneType(),
                    constraints=constraints,
                    side_effects=side_effects,
                )
            if z3_len is not None:
                new_len = z3.Int(f"set_len_{state.pc}")
                constraints.append(z3.And(new_len >= z3_len, new_len <= z3_len + 1))
                s.z3_int = new_len
            side_effects["set_mutation"] = {
                "operation": "add",
                "set_name": getattr(s, "_name", "set"),
                "old_length": z3_len,
                "length_may_increase": True,
            }
        return ModelResult(
            value=SymbolicNoneType(),
            constraints=constraints,
            side_effects=side_effects,
        )


class SetRemoveModel(FunctionModel):
    """Model for set.remove(elem)."""

    name = "remove"
    qualname = "set.remove"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.remove method."""
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error(f"set.{self.name}", state)
        s = get_symbolic_set(args[0]) if args else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if s is not None:
            z3_len = set_length_expr(s)
            exact_item = _exact_hashable_item(args[1] if len(args) > 1 else None)
            concrete_set = _exact_set_payload(s)
            if concrete_set is not None and exact_item is not _UNKNOWN_SET_ITEM:
                if exact_item not in concrete_set:
                    side_effects["raised_exception"] = {
                        "issue_kind": "KEY_ERROR",
                        "exception_type": "KeyError",
                        "message": "set.remove(x): x not in set",
                        "source": "set.remove",
                    }
                    return ModelResult(value=SymbolicNoneType(), side_effects=side_effects)
                old_length = z3_len
                updated_set = set(concrete_set)
                updated_set.remove(exact_item)
                replace_exact_set_value(s, updated_set)
                side_effects["set_mutation"] = {
                    "operation": "remove",
                    "set_name": getattr(s, "_name", "set"),
                    "old_length": old_length,
                    "new_length": set_length_expr(s),
                    "length_decrease": 1,
                }
                return ModelResult(
                    value=SymbolicNoneType(),
                    constraints=constraints,
                    side_effects=side_effects,
                )
            if z3_len is not None:
                constraints.append(z3_len >= 1)
                missing_condition = set_absence_condition(s, args[1] if len(args) > 1 else None)
                if missing_condition is not None:
                    side_effects["potential_exception"] = {
                        "type": "KeyError",
                        "message": "set.remove(x): x not in set",
                        "condition": missing_condition,
                    }
                new_len = z3.Int(f"set_len_{state.pc}")
                constraints.append(new_len == z3_len - 1)
                s.z3_int = new_len
            side_effects["set_mutation"] = {
                "operation": "remove",
                "set_name": getattr(s, "_name", "set"),
                "old_length": z3_len,
                "length_decrease": 1,
            }
        return ModelResult(
            value=SymbolicNoneType(),
            constraints=constraints,
            side_effects=side_effects,
        )


class SetDiscardModel(FunctionModel):
    """Model for set.discard(elem)."""

    name = "discard"
    qualname = "set.discard"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.discard method."""
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error(f"set.{self.name}", state)
        s = get_symbolic_set(args[0]) if args else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if s is not None:
            z3_len = set_length_expr(s)
            exact_item = _exact_hashable_item(args[1] if len(args) > 1 else None)
            concrete_set = _exact_set_payload(s)
            if concrete_set is not None and exact_item is not _UNKNOWN_SET_ITEM:
                old_length = z3_len
                updated_set = set(concrete_set)
                updated_set.discard(exact_item)
                replace_exact_set_value(s, updated_set)
                side_effects["set_mutation"] = {
                    "operation": "discard",
                    "set_name": getattr(s, "_name", "set"),
                    "old_length": old_length,
                    "new_length": set_length_expr(s),
                    "length_may_decrease": True,
                }
                return ModelResult(
                    value=SymbolicNoneType(),
                    constraints=constraints,
                    side_effects=side_effects,
                )
            if z3_len is not None:
                new_len = z3.Int(f"set_len_{state.pc}")
                constraints.append(z3.And(new_len >= z3_len - 1, new_len <= z3_len))
                constraints.append(new_len >= 0)
                s.z3_int = new_len
            side_effects["set_mutation"] = {
                "operation": "discard",
                "set_name": getattr(s, "_name", "set"),
                "old_length": z3_len,
                "length_may_decrease": True,
            }
        return ModelResult(
            value=SymbolicNoneType(),
            constraints=constraints,
            side_effects=side_effects,
        )


_UNKNOWN_SET_ITEM = object()


def _exact_set_payload(value: SymbolicValue) -> set[object] | None:
    payload = value.value
    if isinstance(payload, set):
        return cast("set[object]", payload)
    return None


def _exact_hashable_item(value: object) -> object:
    if isinstance(value, SymbolicValue):
        concrete_value = value.value
        if concrete_value is None:
            return _UNKNOWN_SET_ITEM
        value = concrete_value
    try:
        hash(value)
    except TypeError:
        return _UNKNOWN_SET_ITEM
    return value
