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

from typing import TYPE_CHECKING

from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue

from .shared import (
    FunctionModel,
    ModelResult,
    z3,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

"""Whitespace and affix symbolic string models."""


def _strip_chars_type_error(method: str, value: object) -> str | None:
    if _is_none_value(value) or SymbolicString.resolve(value) is not None:
        return None
    invalid_type = _definite_non_string_type_name(value, none_name="None")
    if invalid_type is None:
        return None
    return f"{method} arg must be None or str"


def _affix_arg_type_error(method: str, value: object) -> str | None:
    if SymbolicString.resolve(value) is not None:
        return None
    invalid_type = _definite_non_string_type_name(value, none_name="None")
    if invalid_type is None:
        return None
    return f"{method}() argument must be str, not {invalid_type}"


def _definite_non_string_type_name(value: object, *, none_name: str) -> str | None:
    if SymbolicString.resolve(value) is not None:
        return None
    if isinstance(value, SymbolicValue):
        if value.value is not None:
            return type(value.value).__name__
        if z3.is_true(value.is_none):
            return none_name
        if z3.is_true(value.is_bool):
            return "bool"
        if z3.is_true(value.is_int):
            return "int"
        return None
    if isinstance(value, SymbolicNoneType) or value is None:
        return none_name
    if isinstance(value, str):
        return None
    return type(value).__name__


def _is_none_value(value: object) -> bool:
    if isinstance(value, SymbolicNoneType) or value is None:
        return True
    return isinstance(value, SymbolicValue) and z3.is_true(value.is_none)


class StrStripModel(FunctionModel):
    """Model for str.strip() - result length <= original length.
    Relationship: len(s.strip()) <= len(s).
    """

    name = "strip"
    qualname = "str.strip"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {1, 2} or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        if len(args) == 2:
            chars_error = _strip_chars_type_error(self.name, args[1])
            if chars_error is not None:
                return ModelResult.method_type_error(self.qualname, state, message=chars_error)
        original = SymbolicString.resolve(args[0]) if args else None
        if original is not None:
            chars = args[1] if len(args) == 2 else None
            result, constraints = original.strip_value(chars, f"strip_{state.pc}", side="both")
            return ModelResult(value=result, constraints=constraints)
        result, base_constraint = SymbolicString.symbolic(f"strip_{state.pc}")
        constraints = [base_constraint]
        return ModelResult(value=result, constraints=constraints)


class StrLstripModel(FunctionModel):
    """Model for str.lstrip() - result length <= original length."""

    name = "lstrip"
    qualname = "str.lstrip"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {1, 2} or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        if len(args) == 2:
            chars_error = _strip_chars_type_error(self.name, args[1])
            if chars_error is not None:
                return ModelResult.method_type_error(self.qualname, state, message=chars_error)
        original = SymbolicString.resolve(args[0]) if args else None
        if original is not None:
            chars = args[1] if len(args) == 2 else None
            result, constraints = original.strip_value(chars, f"lstrip_{state.pc}", side="left")
            return ModelResult(value=result, constraints=constraints)
        result, base_constraint = SymbolicString.symbolic(f"lstrip_{state.pc}")
        constraints = [base_constraint]
        return ModelResult(value=result, constraints=constraints)


class StrRstripModel(FunctionModel):
    """Model for str.rstrip() - result length <= original length."""

    name = "rstrip"
    qualname = "str.rstrip"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {1, 2} or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        if len(args) == 2:
            chars_error = _strip_chars_type_error(self.name, args[1])
            if chars_error is not None:
                return ModelResult.method_type_error(self.qualname, state, message=chars_error)
        original = SymbolicString.resolve(args[0]) if args else None
        if original is not None:
            chars = args[1] if len(args) == 2 else None
            result, constraints = original.strip_value(chars, f"rstrip_{state.pc}", side="right")
            return ModelResult(value=result, constraints=constraints)
        result, base_constraint = SymbolicString.symbolic(f"rstrip_{state.pc}")
        constraints = [base_constraint]
        return ModelResult(value=result, constraints=constraints)


class StrRemovePrefixModel(FunctionModel):
    """Model for str.removeprefix()."""

    name = "removeprefix"
    qualname = "str.removeprefix"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        prefix_error = _affix_arg_type_error(self.name, args[1])
        if prefix_error is not None:
            return ModelResult.method_type_error(self.qualname, state, message=prefix_error)
        original = SymbolicString.resolve(args[0]) if args else None
        if original is not None:
            removed = original.remove_prefix(args[1], f"removeprefix_{state.pc}")
            if removed is not None:
                result, constraints = removed
                return ModelResult(value=result, constraints=constraints)
        result, constraint = SymbolicString.symbolic(f"removeprefix_{state.pc}")
        constraints = [constraint]
        if original is not None:
            constraints.append(result.z3_len <= original.z3_len)
        return ModelResult(value=result, constraints=constraints)


class StrRemoveSuffixModel(FunctionModel):
    """Model for str.removesuffix()."""

    name = "removesuffix"
    qualname = "str.removesuffix"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        suffix_error = _affix_arg_type_error(self.name, args[1])
        if suffix_error is not None:
            return ModelResult.method_type_error(self.qualname, state, message=suffix_error)
        original = SymbolicString.resolve(args[0]) if args else None
        if original is not None:
            removed = original.remove_suffix(args[1], f"removesuffix_{state.pc}")
            if removed is not None:
                result, constraints = removed
                return ModelResult(value=result, constraints=constraints)
        result, constraint = SymbolicString.symbolic(f"removesuffix_{state.pc}")
        constraints = [constraint]
        if original is not None:
            constraints.append(result.z3_len <= original.z3_len)
        return ModelResult(value=result, constraints=constraints)
