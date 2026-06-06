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

"""Async, identity, hash, callable, and representation builtin models."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from ..base import FunctionModel, ModelResult
from ..core.helpers import type_error_side_effect, value_error_side_effect


def _arity_type_error(name: str, args: list[StackValue], state: VMState) -> ModelResult:
    result, constraint = SymbolicValue.symbolic(f"{name}_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects=type_error_side_effect(
            f"builtins.{name}",
            f"{name}() received invalid positional argument count: {len(args)}",
        ),
    )


def _definite_non_async_protocol(value: StackValue) -> bool:
    return value is None or isinstance(
        value, (int, float, bool, str, bytes, list, tuple, dict, set, SymbolicString)
    )


class AiterModel(FunctionModel):
    """Model for aiter() - async iterator."""

    name = "aiter"
    qualname = "builtins.aiter"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _arity_type_error("aiter", args, state)
        if _definite_non_async_protocol(args[0]):
            result, constraint = SymbolicValue.symbolic(f"aiter_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.aiter", "aiter() argument is not an async iterable"
                ),
            )
        result, constraint = SymbolicValue.symbolic(f"aiter_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class AnextModel(FunctionModel):
    """Model for anext() - async next."""

    name = "anext"
    qualname = "builtins.anext"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {1, 2} or kwargs:
            return _arity_type_error("anext", args, state)
        if _definite_non_async_protocol(args[0]):
            result, constraint = SymbolicValue.symbolic(f"anext_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.anext", "anext() argument is not an async iterator"
                ),
            )
        result, constraint = SymbolicValue.symbolic(f"anext_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class IdModel(FunctionModel):
    """Model for id()."""

    name = "id"
    qualname = "builtins.id"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _arity_type_error("id", args, state)
        result, constraint = SymbolicValue.symbolic(f"id_{state.pc}")
        return ModelResult(
            value=result, constraints=[constraint, result.is_int, result.z3_int >= 0]
        )


class HashModel(FunctionModel):
    """Model for hash()."""

    name = "hash"
    qualname = "builtins.hash"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _arity_type_error("hash", args, state)
        obj: StackValue = args[0]
        if isinstance(obj, (int, str, float, tuple, frozenset, type(None))):
            return ModelResult(
                value=SymbolicValue.from_const(
                    hash(
                        cast(
                            "int | str | float | tuple[object, ...] | frozenset[object] | None",
                            obj,
                        )
                    )
                )
            )
        if isinstance(obj, (list, dict, set)):
            result, constraint = SymbolicValue.symbolic(f"hash_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint, result.is_int],
                side_effects=type_error_side_effect(
                    "builtins.hash", "hash() argument is unhashable"
                ),
            )
        result, constraint = SymbolicValue.symbolic(f"hash_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class CallableModel(FunctionModel):
    """Model for callable()."""

    name = "callable"
    qualname = "builtins.callable"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _arity_type_error("callable", args, state)
        obj: StackValue = args[0]
        if not isinstance(obj, SymbolicValue):
            return ModelResult(value=SymbolicValue.from_const(callable(obj)))
        result, constraint = SymbolicValue.symbolic(f"callable_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class ReprModel(FunctionModel):
    """Model for repr()."""

    name = "repr"
    qualname = "builtins.repr"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _arity_type_error("repr", args, state)
        obj: StackValue = args[0]
        if isinstance(obj, SymbolicString):
            if z3.is_string_value(obj.z3_str):
                return ModelResult(value=SymbolicString.from_const(repr(obj.z3_str.as_string())))
            result, constraint = SymbolicString.symbolic(f"repr_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        if not isinstance(obj, SymbolicValue):
            return ModelResult(value=SymbolicString.from_const(repr(obj)))
        result, constraint = SymbolicString.symbolic(f"repr_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class FormatModel(FunctionModel):
    """Model for format()."""

    name = "format"
    qualname = "builtins.format"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {1, 2} or kwargs:
            return _arity_type_error("format", args, state)
        obj: StackValue = args[0]
        spec: StackValue = args[1] if len(args) > 1 else ""
        if isinstance(spec, (int, float, bool, bytes)):
            result, constraint = SymbolicString.symbolic(f"format_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.format", "format() argument 2 must be a string"
                ),
            )
        if isinstance(obj, SymbolicString):
            if isinstance(spec, str) and z3.is_string_value(obj.z3_str):
                try:
                    return ModelResult(
                        value=SymbolicString.from_const(format(obj.z3_str.as_string(), spec))
                    )
                except ValueError as exc:
                    result, constraint = SymbolicString.symbolic(f"format_{state.pc}")
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects=value_error_side_effect("builtins.format", str(exc)),
                    )
            result, constraint = SymbolicString.symbolic(f"format_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        if not isinstance(obj, SymbolicValue) and isinstance(spec, str):
            try:
                return ModelResult(value=SymbolicString.from_const(format(obj, spec)))
            except ValueError as exc:
                result, constraint = SymbolicString.symbolic(f"format_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=value_error_side_effect("builtins.format", str(exc)),
                )
            except TypeError as exc:
                result, constraint = SymbolicString.symbolic(f"format_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=type_error_side_effect("builtins.format", str(exc)),
                )
        result, constraint = SymbolicString.symbolic(f"format_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])
