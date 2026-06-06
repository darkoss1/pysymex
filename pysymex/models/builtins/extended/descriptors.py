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

"""Descriptor and namespace inspection builtin models."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from ..base import FunctionModel, ModelResult
from .helpers import type_error_side_effect


class PropertyModel(FunctionModel):
    """Model for property()."""

    name = "property"
    qualname = "builtins.property"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"property_{state.pc}")
        parameters = ("fget", "fset", "fdel", "doc")
        if (
            len(args) > len(parameters)
            or set(kwargs) - set(parameters)
            or any(name in kwargs for name in parameters[: len(args)])
        ):
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.property", "property() received invalid arguments"
                ),
            )
        return ModelResult(value=result, constraints=[constraint])


class ClassmethodModel(FunctionModel):
    """Model for classmethod()."""

    name = "classmethod"
    qualname = "builtins.classmethod"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            result, constraint = SymbolicValue.symbolic(f"classmethod_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.classmethod",
                    f"classmethod() received invalid positional argument count: {len(args)}",
                ),
            )
        return ModelResult(value=args[0] if args else SymbolicNone())


class StaticmethodModel(FunctionModel):
    """Model for staticmethod()."""

    name = "staticmethod"
    qualname = "builtins.staticmethod"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            result, constraint = SymbolicValue.symbolic(f"staticmethod_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.staticmethod",
                    f"staticmethod() received invalid positional argument count: {len(args)}",
                ),
            )
        return ModelResult(value=args[0] if args else SymbolicNone())


class VarsModel(FunctionModel):
    """Model for vars()."""

    name = "vars"
    qualname = "builtins.vars"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicDict.symbolic(f"vars_{state.pc}")
        if len(args) > 1 or kwargs:
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.vars", "vars() accepts at most one argument"
                ),
            )
        if args and (
            args[0] is None
            or isinstance(
                args[0],
                (
                    int,
                    float,
                    bool,
                    str,
                    bytes,
                    list,
                    tuple,
                    dict,
                    set,
                    SymbolicString,
                    SymbolicList,
                    SymbolicDict,
                ),
            )
        ):
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.vars", "vars() argument must have a __dict__ attribute"
                ),
            )
        return ModelResult(value=result, constraints=[constraint])


class DirModel(FunctionModel):
    """Model for dir()."""

    name = "dir"
    qualname = "builtins.dir"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"dir_{state.pc}")
        if len(args) > 1 or kwargs:
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.dir", "dir() accepts at most one argument"
                ),
            )
        return ModelResult(value=result, constraints=[constraint])


class AsciiModel(FunctionModel):
    """Model for ascii()."""

    name = "ascii"
    qualname = "builtins.ascii"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            result, constraint = SymbolicString.symbolic(f"ascii_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.ascii",
                    f"ascii() takes exactly one argument ({len(args)} given)",
                ),
            )
        if args[0] is None or isinstance(args[0], (int, float, bool, str, bytes)):
            return ModelResult(value=SymbolicString.from_const(ascii(args[0])))
        if isinstance(args[0], SymbolicString) and z3.is_string_value(args[0].z3_str):
            return ModelResult(value=SymbolicString.from_const(ascii(args[0].z3_str.as_string())))
        result, constraint = SymbolicString.symbolic(f"ascii_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])
