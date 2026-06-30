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

"""Attribute mutation and query builtin models."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.models.contracts.results import SideEffects

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

from pysymex._internal.core.state.record import StateConstraints
from pysymex._internal.core.types.base import SymbolicNoneType, SymbolicType
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.common.dynamic import DynamicBuiltinOps
from pysymex._internal.core.solver.feasibility_context import path_may_be_feasible
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult, SideEffectValue


def _modeled_attribute_presence(obj: object, attr_name: str) -> bool | None:
    get_attribute = cast(
        "Callable[[str], tuple[object, bool]] | None",
        getattr(obj, "get_attribute", None),
    )
    if not callable(get_attribute):
        return None
    _value, found = get_attribute(attr_name)
    if found:
        return True
    if DynamicBuiltinOps.has_dynamic_attr_hook(obj):
        return None
    return False


class HasattrModel(FunctionModel):
    """Model for hasattr()."""

    name = "hasattr"
    qualname = "builtins.hasattr"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            result, constraint = SymbolicValue.symbolic_bool(f"hasattr_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.hasattr",
                    f"hasattr() received invalid positional argument count: {len(args)}",
                ),
            )
        obj: StackValue = args[0]
        name = SymbolicString.concrete_literal(args[1])
        if name is None and (args[1] is None or isinstance(args[1], (int, float, bool, bytes))):
            result, constraint = SymbolicValue.symbolic_bool(f"hasattr_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.hasattr",
                    "attribute name must be a string",
                ),
            )
        if isinstance(obj, SymbolicValue) and isinstance(name, str):
            modeled_object = getattr(obj, "_modeled_object", None)
            presence = _modeled_attribute_presence(modeled_object, name)
            if presence is not None:
                return ModelResult(value=SymbolicValue.from_const(presence))
        if isinstance(obj, SymbolicString) and isinstance(name, str):
            literal_obj = SymbolicString.concrete_literal(obj)
            if literal_obj is not None:
                return ModelResult(value=SymbolicValue.from_const(hasattr(literal_obj, name)))
        if not isinstance(obj, SymbolicType) and isinstance(name, str):
            return ModelResult(value=SymbolicValue.from_const(hasattr(obj, name)))
        result, constraint = SymbolicValue.symbolic_bool(f"hasattr_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class SetattrModel(FunctionModel):
    """Model for setattr()."""

    name = "setattr"
    qualname = "builtins.setattr"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 3 or kwargs:
            return ModelResult(
                value=SymbolicNoneType("none"),
                side_effects=SideEffects.type_error(
                    "builtins.setattr",
                    f"setattr() received invalid positional argument count: {len(args)}",
                ),
            )
        if SymbolicString.concrete_literal(args[1]) is None and (
            args[1] is None or isinstance(args[1], (int, float, bool, bytes))
        ):
            return ModelResult(
                value=SymbolicNoneType("none"),
                side_effects=SideEffects.type_error(
                    "builtins.setattr",
                    "attribute name must be a string",
                ),
            )
        side_effects: dict[str, SideEffectValue] = {"mutates_arg": 0}
        if len(args) >= 2:
            obj = args[0]
            attr_name = args[1]
            literal_attr_name = SymbolicString.concrete_literal(attr_name)
            attr_name_str = literal_attr_name or "<dynamic>"
            if obj is None or isinstance(obj, SymbolicNoneType):
                side_effects["raised_exception"] = {
                    "issue_kind": "ATTRIBUTE_ERROR",
                    "exception_type": "AttributeError",
                    "message": f"Cannot set attribute '{attr_name_str}' on None",
                    "source": "builtins.setattr",
                }
                return ModelResult(value=SymbolicNoneType("none"), side_effects=side_effects)
            if isinstance(obj, SymbolicValue) and DynamicBuiltinOps.must_be_none(
                obj,
                list(state.path_constraints),
                known_sat_prefix_len=StateConstraints.known_sat_prefix_len(state),
                inconclusive_path_prefix_len=state.last_inconclusive_feasibility_len,
            ):
                side_effects["raised_exception"] = {
                    "issue_kind": "ATTRIBUTE_ERROR",
                    "exception_type": "AttributeError",
                    "message": f"Cannot set attribute '{attr_name_str}' on symbolic None",
                    "source": "builtins.setattr",
                }
                return ModelResult(value=SymbolicNoneType("none"), side_effects=side_effects)
            if isinstance(obj, SymbolicValue) and path_may_be_feasible(
                [*list(state.path_constraints), obj.is_none],
            ):
                side_effects["raised_exception"] = {
                    "issue_kind": "ATTRIBUTE_ERROR",
                    "exception_type": "AttributeError",
                    "message": f"Cannot safely set attribute '{attr_name_str}' when receiver may be None",
                    "source": "builtins.setattr",
                }
                return ModelResult(value=SymbolicNoneType("none"), side_effects=side_effects)
            if isinstance(obj, SymbolicValue):
                modeled_object = getattr(obj, "_modeled_object", None)
                set_attribute = getattr(modeled_object, "set_attribute", None)
                if callable(set_attribute) and len(args) >= 3 and literal_attr_name is not None:
                    if set_attribute(attr_name_str, args[2]):
                        side_effects["attribute_mutation"] = {
                            "target_index": 0,
                            "attr_name": attr_name_str,
                            "status": "applied",
                            "source": "builtins.setattr",
                        }
                    else:
                        side_effects["raised_exception"] = {
                            "issue_kind": "ATTRIBUTE_ERROR",
                            "exception_type": "AttributeError",
                            "message": f"Cannot set attribute '{attr_name_str}'",
                            "source": "builtins.setattr",
                        }
                    return ModelResult(value=SymbolicNoneType("none"), side_effects=side_effects)
                side_effects["raised_exception"] = {
                    "issue_kind": "ATTRIBUTE_ERROR",
                    "exception_type": "AttributeError",
                    "message": f"Cannot prove setattr target is valid for attribute '{attr_name_str}'",
                    "source": "builtins.setattr",
                }
                return ModelResult(value=SymbolicNoneType("none"), side_effects=side_effects)
            if not isinstance(obj, SymbolicValue) and isinstance(attr_name, str):
                if len(args) >= 3:
                    try:
                        setattr(obj, attr_name, args[2])
                        side_effects["attribute_mutation"] = {
                            "target_index": 0,
                            "attr_name": attr_name,
                            "status": "applied",
                            "source": "builtins.setattr",
                        }
                    except (AttributeError, TypeError) as exc:
                        side_effects["raised_exception"] = {
                            "issue_kind": "ATTRIBUTE_ERROR",
                            "exception_type": type(exc).__name__,
                            "message": str(exc),
                            "source": "builtins.setattr",
                        }
        return ModelResult(value=SymbolicNoneType("none"), side_effects=side_effects)


class DelattrModel(FunctionModel):
    """Model for delattr()."""

    name = "delattr"
    qualname = "builtins.delattr"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return ModelResult(
                value=SymbolicNoneType("none"),
                side_effects=SideEffects.type_error(
                    "builtins.delattr",
                    f"delattr() received invalid positional argument count: {len(args)}",
                ),
            )
        if SymbolicString.concrete_literal(args[1]) is None and (
            args[1] is None or isinstance(args[1], (int, float, bool, bytes))
        ):
            return ModelResult(
                value=SymbolicNoneType("none"),
                side_effects=SideEffects.type_error(
                    "builtins.delattr",
                    "attribute name must be a string",
                ),
            )
        side_effects: dict[str, SideEffectValue] = {"mutates_arg": 0}
        obj = args[0]
        attr_name = SymbolicString.concrete_literal(args[1])
        if not isinstance(obj, SymbolicValue) and attr_name is not None:
            try:
                delattr(obj, attr_name)
            except (AttributeError, TypeError) as exc:
                side_effects["raised_exception"] = {
                    "issue_kind": "ATTRIBUTE_ERROR",
                    "exception_type": type(exc).__name__,
                    "message": str(exc),
                    "source": "builtins.delattr",
                }
        return ModelResult(value=SymbolicNoneType("none"), side_effects=side_effects)
