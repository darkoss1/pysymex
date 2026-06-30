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

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.types.scalars.string_search import (
    concrete_string_slice_args,
    string_slice_bounds_are_definitely_invalid,
    string_type_name_if_definitely_not_string,
)
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.models.builtins.types.containers.strings.shared import (
    FunctionModel,
    ModelResult,
    SymbolicValue,
    z3,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

"""Count and containment symbolic string search models."""

_SLICE_INDEX_TYPE_ERROR = "slice indices must be integers or None or have an __index__ method"


class StrCountModel(FunctionModel):
    """Model for str.count() - count bounded by string length.
    Relationships:
    - count >= 0
    - count <= len(s) (can't have more occurrences than characters).
    """

    name = "count"
    qualname = "str.count"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3, 4} or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        invalid_type = string_type_name_if_definitely_not_string(args[1])
        if invalid_type is not None:
            return ModelResult.method_type_error(
                self.qualname,
                state,
                message=f"{self.name}() argument 1 must be str, not {invalid_type}",
            )
        if string_slice_bounds_are_definitely_invalid(args[2:]):
            return ModelResult.method_type_error(
                self.qualname,
                state,
                message=_SLICE_INDEX_TYPE_ERROR,
            )
        exact = _exact_count_result(args)
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        original = SymbolicString.resolve(args[0]) if args else None
        substring = SymbolicString.resolve(args[1]) if len(args) > 1 else None
        result, constraints = ModelResult.symbolic_int(f"count_{state.pc}")
        constraints.append(result.z3_int >= 0)
        if original is not None:
            binary_count_constraints = _binary_one_count_constraints(args, original, result)
            if binary_count_constraints:
                constraints.extend(binary_count_constraints)
                return ModelResult(value=result, constraints=constraints)
            constraints.append(result.z3_int <= original.z3_len)
            constraints.extend(_character_count_upper_bound_constraints(args, original, result))
            if substring is not None:
                non_empty_sub = substring.z3_len > 0
                has_sub = z3.Contains(original.z3_str, substring.z3_str)
                constraints.append(z3.Implies(z3.And(non_empty_sub, result.z3_int > 0), has_sub))
                constraints.append(
                    z3.Implies(z3.And(non_empty_sub, result.z3_int == 0), z3.Not(has_sub)),
                )
                constraints.append(
                    z3.Implies(substring.z3_len > original.z3_len, result.z3_int == 0),
                )
        return ModelResult(value=result, constraints=constraints)


class StrContainsModel(FunctionModel):
    """Model for 'in' operator on strings - uses Z3 Contains."""

    name = "__contains__"
    qualname = "str.__contains__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        invalid_type = string_type_name_if_definitely_not_string(args[1])
        if invalid_type is not None:
            return ModelResult.method_type_error(
                self.qualname,
                state,
                message=f"'in <string>' requires string as left operand, not {invalid_type}",
            )
        exact = _exact_contains_result(args)
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        haystack = SymbolicString.resolve(args[0]) if args else None
        needle = SymbolicString.resolve(args[1]) if len(args) > 1 else None
        if haystack is not None and needle is not None:
            result_bool = z3.Contains(haystack.z3_str, needle.z3_str)
            result = SymbolicValue(
                _name=f"contains_{state.pc}",
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=result_bool,
                is_bool=Z3_TRUE,
            )
            return ModelResult(value=result, constraints=[])
        return ModelResult.bool(f"contains_{state.pc}")


def _binary_one_count_constraints(
    args: list[StackValue],
    original: SymbolicString,
    result: SymbolicValue,
) -> list[z3.BoolRef]:
    """Return exact zero-count facts for unsliced ``bin(value).count("1")`` calls."""
    if len(args) != 2:
        return []
    if SymbolicString.concrete_literal(args[1]) != "1":
        return []
    source = original.binary_integer_source
    if source is None:
        return []
    return [
        z3.Implies(result.z3_int == 0, source == 0),
        z3.Implies(source == 0, result.z3_int == 0),
    ]


def _character_count_upper_bound_constraints(
    args: list[StackValue],
    original: SymbolicString,
    result: SymbolicValue,
) -> list[z3.BoolRef]:
    substring = SymbolicString.concrete_literal(args[1]) if len(args) > 1 else None
    if substring is None or len(substring) != 1:
        return []
    upper_bound = original.character_count_upper_bound(substring)
    if upper_bound is None:
        return []
    return [result.z3_int <= upper_bound]


def _exact_count_result(args: list[StackValue]) -> int | None:
    original = SymbolicString.concrete_literal(args[0])
    substring = SymbolicString.concrete_literal(args[1]) if len(args) > 1 else None
    slice_args = concrete_string_slice_args(args[2:])
    if original is None or substring is None or slice_args is None:
        return None
    return original.count(substring, *slice_args)


def _exact_contains_result(args: list[StackValue]) -> bool | None:
    if len(args) != 2:
        return None
    haystack = SymbolicString.concrete_literal(args[0])
    needle = SymbolicString.concrete_literal(args[1])
    if haystack is None or needle is None:
        return None
    return needle in haystack
