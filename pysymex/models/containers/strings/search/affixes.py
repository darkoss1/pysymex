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

from pysymex.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO

from ..shared import (
    FunctionModel,
    ModelResult,
    SymbolicString,
    SymbolicValue,
    concrete_string_literal,
    get_symbolic_string,
    method_type_error_result,
    model_bool_result,
    z3,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

"""Replace and affix symbolic string search models."""


class StrReplaceModel(FunctionModel):
    """Model for str.replace() - result length relationship.
    Relationships:
    - If old and new have same length: result length == original length
    - If old is longer: result length <= original length
    - If new is longer: result length >= original length
    """

    name = "replace"
    qualname = "str.replace"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {3, 4} or kwargs:
            return method_type_error_result(self.qualname, state)
        original = get_symbolic_string(args[0]) if args else None
        old_str = get_symbolic_string(args[1]) if len(args) > 1 else None
        get_symbolic_string(args[2]) if len(args) > 2 else None
        exact = _exact_replace_result(args)
        if exact is not None:
            return ModelResult(value=SymbolicString.from_const(exact))
        result, base_constraint = SymbolicString.symbolic(f"replace_{state.pc}")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len >= 0)
            if old_str is not None:
                old_not_found = z3.Not(z3.Contains(original.z3_str, old_str.z3_str))
                constraints.append(z3.Implies(old_not_found, result.z3_len == original.z3_len))
        return ModelResult(value=result, constraints=constraints)


class StrStartswithModel(FunctionModel):
    """Model for str.startswith() - uses Z3 PrefixOf."""

    name = "startswith"
    qualname = "str.startswith"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3, 4} or kwargs:
            return method_type_error_result(self.qualname, state)
        original = get_symbolic_string(args[0]) if args else None
        prefix = get_symbolic_string(args[1]) if len(args) > 1 else None
        if original is not None and prefix is not None:
            result_bool = z3.PrefixOf(prefix.z3_str, original.z3_str)
            result = SymbolicValue(
                _name=f"startswith_{state.pc}",
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=result_bool,
                is_bool=Z3_TRUE,
            )
            return ModelResult(value=result, constraints=[])
        return model_bool_result(f"startswith_{state.pc}")


class StrEndswithModel(FunctionModel):
    """Model for str.endswith() - uses Z3 SuffixOf."""

    name = "endswith"
    qualname = "str.endswith"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3, 4} or kwargs:
            return method_type_error_result(self.qualname, state)
        original = get_symbolic_string(args[0]) if args else None
        suffix = get_symbolic_string(args[1]) if len(args) > 1 else None
        if original is not None and suffix is not None:
            result_bool = z3.SuffixOf(suffix.z3_str, original.z3_str)
            result = SymbolicValue(
                _name=f"endswith_{state.pc}",
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=result_bool,
                is_bool=Z3_TRUE,
            )
            return ModelResult(value=result, constraints=[])
        return model_bool_result(f"endswith_{state.pc}")


__all__ = ["StrEndswithModel", "StrReplaceModel", "StrStartswithModel"]


def _exact_replace_result(args: list[StackValue]) -> str | None:
    original = concrete_string_literal(args[0])
    old = concrete_string_literal(args[1]) if len(args) > 1 else None
    new = concrete_string_literal(args[2]) if len(args) > 2 else None
    if original is None or old is None or new is None:
        return None
    count = _concrete_int(args[3]) if len(args) > 3 else -1
    if count is None:
        return None
    return original.replace(old, new, count)


def _concrete_int(value: object) -> int | None:
    if isinstance(value, SymbolicValue):
        value = value.value
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return None
