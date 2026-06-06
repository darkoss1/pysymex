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


if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.state.record import known_sat_prefix_len_for_state
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from ..base import FunctionModel, ModelResult, SideEffectValue
from .helpers import (
    modeled_object_get_attribute as _modeled_object_get_attribute,
    modeled_object_has_dynamic_attribute_hook as _modeled_object_has_dynamic_attribute_hook,
    literal_string_value as _literal_string_value,
    must_be_none as _must_be_none,
    symbolic_builtin_has_attr as _symbolic_builtin_has_attr,
    type_error_side_effect as _type_error_side_effect,
)


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
                side_effects=_type_error_side_effect(
                    "builtins.getattr",
                    f"getattr() received invalid positional argument count: {len(args)}",
                ),
            )
        obj: StackValue = args[0]
        name = _literal_string_value(args[1])
        has_default = len(args) > 2
        default: StackValue | None = args[2] if len(args) > 2 else None
        if name is None and (args[1] is None or isinstance(args[1], (int, float, bool, bytes))):
            result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=_type_error_side_effect(
                    "builtins.getattr", "attribute name must be a string"
                ),
            )
        if isinstance(obj, SymbolicString) and isinstance(name, str):
            literal_obj = _literal_string_value(obj)
            if literal_obj is not None:
                try:
                    return ModelResult(value=getattr(literal_obj, name))
                except AttributeError:
                    if has_default:
                        return ModelResult(value=default)
                    result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
                    side_effects: dict[str, SideEffectValue] = {
                        "raised_exception": {
                            "issue_kind": "ATTRIBUTE_ERROR",
                            "exception_type": "AttributeError",
                            "message": f"Attribute access '{name}' failed",
                            "source": "builtins.getattr",
                        }
                    }
                    return ModelResult(
                        value=result, constraints=[constraint], side_effects=side_effects
                    )
        if not isinstance(obj, (SymbolicValue, SymbolicString)) and isinstance(name, str):
            try:
                return ModelResult(value=getattr(obj, name))
            except AttributeError:
                if has_default:
                    return ModelResult(value=default)
                result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
                side_effects: dict[str, SideEffectValue] = {
                    "raised_exception": {
                        "issue_kind": "ATTRIBUTE_ERROR",
                        "exception_type": "AttributeError",
                        "message": f"Attribute access '{name}' failed",
                        "source": "builtins.getattr",
                    }
                }
                return ModelResult(
                    value=result, constraints=[constraint], side_effects=side_effects
                )
        if not has_default and isinstance(name, str):
            if obj is None or isinstance(obj, SymbolicNone):
                result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
                side_effects = {
                    "raised_exception": {
                        "issue_kind": "ATTRIBUTE_ERROR",
                        "exception_type": "AttributeError",
                        "message": f"Attribute access '{name}' on None",
                        "source": "builtins.getattr",
                    }
                }
                return ModelResult(
                    value=result, constraints=[constraint], side_effects=side_effects
                )
            if isinstance(obj, SymbolicValue) and _must_be_none(
                obj,
                list(state.path_constraints),
                known_sat_prefix_len=known_sat_prefix_len_for_state(state),
                inconclusive_path_prefix_len=state.last_inconclusive_feasibility_len,
            ):
                result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
                side_effects = {
                    "raised_exception": {
                        "issue_kind": "ATTRIBUTE_ERROR",
                        "exception_type": "AttributeError",
                        "message": f"Attribute access '{name}' on symbolic None",
                        "source": "builtins.getattr",
                    }
                }
                return ModelResult(
                    value=result, constraints=[constraint], side_effects=side_effects
                )
            if isinstance(obj, SymbolicValue):
                modeled_object = getattr(obj, "_modeled_object", None)
                if modeled_object is not None:
                    modeled_attr = _modeled_object_get_attribute(modeled_object, name)
                    if modeled_attr is not None:
                        attr_value, found = modeled_attr
                        if found:
                            return ModelResult(value=cast("StackValue", attr_value))
                        if _modeled_object_has_dynamic_attribute_hook(modeled_object):
                            result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
                            return ModelResult(value=result, constraints=[constraint])
                        result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
                        side_effects: dict[str, SideEffectValue] = {
                            "raised_exception": {
                                "issue_kind": "ATTRIBUTE_ERROR",
                                "exception_type": "AttributeError",
                                "message": f"Attribute access '{name}' failed",
                                "source": "builtins.getattr",
                            }
                        }
                        return ModelResult(
                            value=result, constraints=[constraint], side_effects=side_effects
                        )

                has_attr = _symbolic_builtin_has_attr(obj, name)
                if has_attr is False:
                    result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
                    side_effects = {
                        "raised_exception": {
                            "issue_kind": "ATTRIBUTE_ERROR",
                            "exception_type": "AttributeError",
                            "message": f"Attribute access '{name}' unsupported on symbolic builtin type",
                            "source": "builtins.getattr",
                        }
                    }
                    return ModelResult(
                        value=result, constraints=[constraint], side_effects=side_effects
                    )
                if not name.startswith("__"):
                    result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
                    return ModelResult(value=result, constraints=[constraint])
        result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])
