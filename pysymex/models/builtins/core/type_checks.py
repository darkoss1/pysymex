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

"""type(), isinstance(), and print() builtin models."""

from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.typed_results import (
    model_bool_result,
    symbolic_bool_result,
)

from ..base import FunctionModel, ModelResult, none_model_result
from .helpers import type_error_side_effect


class PrintModel(FunctionModel):
    """Model for print() - side effect only."""

    name = "print"
    qualname = "builtins.print"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if set(kwargs) - {"sep", "end", "file", "flush"}:
            result, constraint = SymbolicValue.symbolic(f"print_invalid_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.print", "print() received an unexpected keyword argument"
                ),
            )
        for name in ("sep", "end"):
            value = kwargs.get(name)
            if value is not None and isinstance(value, (int, float, bool, bytes, list, dict, set)):
                result, constraint = SymbolicValue.symbolic(f"print_invalid_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=type_error_side_effect(
                        "builtins.print", f"print() {name} must be None or a string"
                    ),
                )
        return none_model_result()


class TypeModel(FunctionModel):
    """Model for type()."""

    name = "type"
    qualname = "builtins.type"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {1, 3} or kwargs:
            result, constraint = SymbolicValue.symbolic(f"type_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.type", "type() takes 1 or 3 arguments"
                ),
            )
        if len(args) == 1:
            obj = args[0]
            if isinstance(obj, SymbolicString):
                return ModelResult(value=SymbolicValue.from_const(str))
            if isinstance(obj, SymbolicList):
                return ModelResult(value=SymbolicValue.from_const(list))
            if isinstance(obj, SymbolicDict):
                return ModelResult(value=SymbolicValue.from_const(dict))
            if obj is None:
                return ModelResult(value=SymbolicValue.from_const(type(None)))
            if isinstance(obj, bool):
                return ModelResult(value=SymbolicValue.from_const(bool))
            if isinstance(obj, int):
                return ModelResult(value=SymbolicValue.from_const(int))
            if isinstance(obj, float):
                return ModelResult(value=SymbolicValue.from_const(float))
            if isinstance(obj, str):
                return ModelResult(value=SymbolicValue.from_const(str))
            if isinstance(obj, bytes):
                return ModelResult(value=SymbolicValue.from_const(bytes))
            if isinstance(obj, list):
                return ModelResult(value=SymbolicValue.from_const(list))
            if isinstance(obj, tuple):
                return ModelResult(value=SymbolicValue.from_const(tuple))
            if isinstance(obj, dict):
                return ModelResult(value=SymbolicValue.from_const(dict))
            if isinstance(obj, set):
                return ModelResult(value=SymbolicValue.from_const(set))
            if isinstance(obj, frozenset):
                return ModelResult(value=SymbolicValue.from_const(frozenset))
            if isinstance(obj, type):
                return ModelResult(value=SymbolicValue.from_const(type))
        if len(args) == 3:
            name, bases, namespace = args
            if (
                name is None
                or isinstance(name, (int, float, bool, bytes, list, tuple, dict, set))
                or (
                    not isinstance(bases, tuple)
                    and (bases is None or isinstance(bases, (int, float, bool, str, bytes, list)))
                )
                or (
                    not isinstance(namespace, dict)
                    and (
                        namespace is None
                        or isinstance(namespace, (int, float, bool, str, bytes, list, tuple))
                    )
                )
            ):
                result, constraint = SymbolicValue.symbolic(f"type_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=type_error_side_effect(
                        "builtins.type", "type() class construction arguments have invalid types"
                    ),
                )
        result, constraint = SymbolicValue.symbolic(f"type_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class IsinstanceModel(FunctionModel):
    """Model for isinstance()."""

    name = "isinstance"
    qualname = "builtins.isinstance"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            result, constraints = symbolic_bool_result(f"isinstance_{state.pc}")
            return ModelResult(
                value=result,
                constraints=constraints,
                side_effects=type_error_side_effect(
                    "builtins.isinstance",
                    f"isinstance() received invalid positional argument count: {len(args)}",
                ),
            )
        obj, types = args[0], args[1]
        if types is None or isinstance(types, (int, float, bool, str, bytes, list, dict, set)):
            result, constraints = symbolic_bool_result(f"isinstance_{state.pc}")
            return ModelResult(
                value=result,
                constraints=constraints,
                side_effects=type_error_side_effect(
                    "builtins.isinstance", "isinstance() arg 2 must be a type"
                ),
            )

        # Determine the target Z3 constraint for the type check
        type_expr = None
        if isinstance(obj, SymbolicValue):
            if types is int:
                type_expr = obj.is_int
            elif types is bool:
                type_expr = obj.is_bool
            elif types is str:
                type_expr = obj.is_str
            elif types is float:
                type_expr = obj.is_float
            elif types is list:
                type_expr = obj.is_list
            elif types is dict:
                type_expr = obj.is_dict

        if type_expr is not None:
            # We return a new symbolic boolean, but we tie its truth value
            # EXACTLY to the type constraint of the object.
            obj_name = str(getattr(obj, "name")) if hasattr(obj, "name") else "obj"
            result, constraints = symbolic_bool_result(f"isinstance_check_{obj_name}_{state.pc}")
            constraints.append(result.z3_bool == type_expr)
            return ModelResult(
                value=result,
                constraints=constraints,
            )

        if isinstance(obj, SymbolicString) and types is str:
            return ModelResult(value=True)
        if isinstance(obj, SymbolicList) and types is list:
            return ModelResult(value=True)
        if isinstance(obj, SymbolicDict) and types is dict:
            return ModelResult(value=True)
        if isinstance(types, type) and not isinstance(obj, SymbolicValue):
            return ModelResult(value=bool(isinstance(obj, types)))

        return model_bool_result(f"isinstance_{state.pc}")
