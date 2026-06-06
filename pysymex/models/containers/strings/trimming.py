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

from .shared import (
    FunctionModel,
    ModelResult,
    SymbolicString,
    concrete_string_literal,
    get_symbolic_string,
    method_type_error_result,
    z3,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

"""Whitespace and affix symbolic string models."""


def _concrete_strip_chars(args: list[StackValue]) -> tuple[bool, str | None]:
    if len(args) == 1:
        return True, None
    if args[1] is None:
        return True, None
    literal = concrete_string_literal(args[1])
    return (True, literal) if literal is not None else (False, None)


class StrStripModel(FunctionModel):
    """Model for str.strip() - result length <= original length.
    Relationship: len(s.strip()) <= len(s)
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
            return method_type_error_result(self.qualname, state)
        literal = concrete_string_literal(args[0]) if args else None
        has_concrete_chars, chars = _concrete_strip_chars(args)
        if literal is not None and has_concrete_chars:
            return ModelResult(value=SymbolicString.from_const(literal.strip(chars)))
        original = get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"strip_{state.pc}")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len <= original.z3_len)
            constraints.append(result.z3_len >= 0)
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
            return method_type_error_result(self.qualname, state)
        literal = concrete_string_literal(args[0]) if args else None
        has_concrete_chars, chars = _concrete_strip_chars(args)
        if literal is not None and has_concrete_chars:
            return ModelResult(value=SymbolicString.from_const(literal.lstrip(chars)))
        original = get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"lstrip_{state.pc}")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len <= original.z3_len)
            constraints.append(result.z3_len >= 0)
            constraints.append(z3.SuffixOf(result.z3_str, original.z3_str))
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
            return method_type_error_result(self.qualname, state)
        literal = concrete_string_literal(args[0]) if args else None
        has_concrete_chars, chars = _concrete_strip_chars(args)
        if literal is not None and has_concrete_chars:
            return ModelResult(value=SymbolicString.from_const(literal.rstrip(chars)))
        original = get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"rstrip_{state.pc}")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len <= original.z3_len)
            constraints.append(result.z3_len >= 0)
            constraints.append(z3.PrefixOf(result.z3_str, original.z3_str))
        return ModelResult(value=result, constraints=constraints)


class StrRemovePrefixModel(FunctionModel):
    """Model for str.removeprefix()."""

    name = "removeprefix"
    qualname = "str.removeprefix"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return method_type_error_result(self.qualname, state)
        original = get_symbolic_string(args[0]) if args else None
        prefix = get_symbolic_string(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicString.symbolic(f"removeprefix_{state.pc}")
        constraints = [constraint]
        if original is not None:
            constraints.append(result.z3_len <= original.z3_len)
            if prefix is not None:
                is_prefix = z3.PrefixOf(prefix.z3_str, original.z3_str)
                constraints.append(
                    z3.Implies(is_prefix, result.z3_len == original.z3_len - prefix.z3_len)
                )
                constraints.append(z3.Implies(z3.Not(is_prefix), result.z3_len == original.z3_len))
        return ModelResult(value=result, constraints=constraints)


class StrRemoveSuffixModel(FunctionModel):
    """Model for str.removesuffix()."""

    name = "removesuffix"
    qualname = "str.removesuffix"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return method_type_error_result(self.qualname, state)
        original = get_symbolic_string(args[0]) if args else None
        suffix = get_symbolic_string(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicString.symbolic(f"removesuffix_{state.pc}")
        constraints = [constraint]
        if original is not None:
            constraints.append(result.z3_len <= original.z3_len)
            if suffix is not None:
                is_suffix = z3.SuffixOf(suffix.z3_str, original.z3_str)
                constraints.append(
                    z3.Implies(is_suffix, result.z3_len == original.z3_len - suffix.z3_len)
                )
                constraints.append(z3.Implies(z3.Not(is_suffix), result.z3_len == original.z3_len))
        return ModelResult(value=result, constraints=constraints)
