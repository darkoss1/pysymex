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

"""getattr() builtin model."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.models.contracts.results import SideEffects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

from pysymex._internal.core.state.record import StateConstraints
from pysymex._internal.core.types.base import SymbolicNoneType, SymbolicType
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.common.dynamic import DynamicBuiltinOps
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult, SideEffectValue


class GetattrModel(FunctionModel):
    """Model for getattr()."""

    name = "getattr"
    qualname = "builtins.getattr"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3} or kwargs:
            result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.getattr",
                    f"getattr() received invalid positional argument count: {len(args)}",
                ),
            )
        obj: StackValue = args[0]
        name = SymbolicString.concrete_literal(args[1])
        has_default = len(args) > 2
        default: StackValue | None = args[2] if len(args) > 2 else None
        if name is None and (args[1] is None or isinstance(args[1], (int, float, bool, bytes))):
            result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.getattr",
                    "attribute name must be a string",
                ),
            )
        if isinstance(obj, SymbolicString) and isinstance(name, str):
            literal_obj = SymbolicString.concrete_literal(obj)
            if literal_obj is not None:
                try:
                    return ModelResult(value=getattr(literal_obj, name))
                except AttributeError:
                    if has_default:
                        return ModelResult(value=default)
                    result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
                    literal_attr_error_effects: dict[str, SideEffectValue] = {
                        "raised_exception": {
                            "issue_kind": "ATTRIBUTE_ERROR",
                            "exception_type": "AttributeError",
                            "message": f"Attribute access '{name}' failed",
                            "source": "builtins.getattr",
                        },
                    }
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects=literal_attr_error_effects,
                    )
        if not isinstance(obj, SymbolicType) and isinstance(name, str):
            try:
                return ModelResult(value=getattr(obj, name))
            except AttributeError:
                if has_default:
                    return ModelResult(value=default)
                result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
                concrete_attr_error_effects: dict[str, SideEffectValue] = {
                    "raised_exception": {
                        "issue_kind": "ATTRIBUTE_ERROR",
                        "exception_type": "AttributeError",
                        "message": f"Attribute access '{name}' failed",
                        "source": "builtins.getattr",
                    },
                }
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=concrete_attr_error_effects,
                )
        if not has_default and isinstance(name, str):
            if obj is None or isinstance(obj, SymbolicNoneType):
                result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
                none_attr_error_effects: dict[str, SideEffectValue] = {
                    "raised_exception": {
                        "issue_kind": "ATTRIBUTE_ERROR",
                        "exception_type": "AttributeError",
                        "message": f"Attribute access '{name}' on None",
                        "source": "builtins.getattr",
                    },
                }
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=none_attr_error_effects,
                )
            if isinstance(obj, SymbolicValue) and DynamicBuiltinOps.must_be_none(
                obj,
                list(state.path_constraints),
                known_sat_prefix_len=StateConstraints.known_sat_prefix_len(state),
                inconclusive_path_prefix_len=state.last_inconclusive_feasibility_len,
            ):
                result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
                symbolic_none_attr_error_effects: dict[str, SideEffectValue] = {
                    "raised_exception": {
                        "issue_kind": "ATTRIBUTE_ERROR",
                        "exception_type": "AttributeError",
                        "message": f"Attribute access '{name}' on symbolic None",
                        "source": "builtins.getattr",
                    },
                }
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=symbolic_none_attr_error_effects,
                )
            if isinstance(obj, SymbolicValue):
                modeled_object = getattr(obj, "_modeled_object", None)
                if modeled_object is not None:
                    modeled_attr = DynamicBuiltinOps.get_modeled_attr(modeled_object, name)
                    if modeled_attr is not None:
                        attr_value, found = modeled_attr
                        if found:
                            return ModelResult(value=cast("StackValue", attr_value))
                        if DynamicBuiltinOps.has_dynamic_attr_hook(modeled_object):
                            result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
                            return ModelResult(value=result, constraints=[constraint])
                        result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
                        modeled_attr_error_effects: dict[str, SideEffectValue] = {
                            "raised_exception": {
                                "issue_kind": "ATTRIBUTE_ERROR",
                                "exception_type": "AttributeError",
                                "message": f"Attribute access '{name}' failed",
                                "source": "builtins.getattr",
                            },
                        }
                        return ModelResult(
                            value=result,
                            constraints=[constraint],
                            side_effects=modeled_attr_error_effects,
                        )

                has_attr = DynamicBuiltinOps.has_symbolic_attr(obj, name)
                if has_attr is False:
                    result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
                    symbolic_builtin_attr_error_effects: dict[str, SideEffectValue] = {
                        "raised_exception": {
                            "issue_kind": "ATTRIBUTE_ERROR",
                            "exception_type": "AttributeError",
                            "message": f"Attribute access '{name}' unsupported on symbolic builtin type",
                            "source": "builtins.getattr",
                        },
                    }
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects=symbolic_builtin_attr_error_effects,
                    )
                if not name.startswith("__"):
                    result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
                    return ModelResult(value=result, constraints=[constraint])
        result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])
