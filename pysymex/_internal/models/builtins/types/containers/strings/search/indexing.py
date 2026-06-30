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
from pysymex._internal.models.contracts.results import SideEffects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

"""Index-style symbolic string search models."""

_SLICE_INDEX_TYPE_ERROR = "slice indices must be integers or None or have an __index__ method"


class StrFindModel(FunctionModel):
    """Model for str.find() - uses Z3 IndexOf with proper bounds.
    Relationships:
    - Returns -1 if not found
    - Returns index >= 0 and < len(s) if found
    - Index + len(sub) <= len(s).
    """

    name = "find"
    qualname = "str.find"

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
            return _substring_type_error_result(self, invalid_type, state)
        if string_slice_bounds_are_definitely_invalid(args[2:]):
            return _slice_type_error_result(self.qualname, state)
        exact = _exact_find_result(args, reverse=False)
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        original = SymbolicString.resolve(args[0]) if args else None
        substring = SymbolicString.resolve(args[1]) if len(args) > 1 else None
        if original is not None and substring is not None:
            idx = z3.IndexOf(original.z3_str, substring.z3_str, Z3_ZERO)
            result = SymbolicValue(
                _name=f"find_{state.pc}",
                z3_int=idx,
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
            )
            constraints = [
                z3.Or(idx == -1, z3.And(idx >= 0, idx < original.z3_len)),
                z3.Implies(idx >= 0, idx + substring.z3_len <= original.z3_len),
            ]
            return ModelResult(value=result, constraints=constraints)
        result, constraints = ModelResult.symbolic_int(f"find_{state.pc}")
        constraints.append(result.z3_int >= -1)
        return ModelResult(
            value=result,
            constraints=constraints,
        )


class StrIndexModel(FunctionModel):
    """Model for str.index() - like find but raises ValueError if not found.
    Bug detection: Can find cases where substring might not exist.
    """

    name = "index"
    qualname = "str.index"

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
            return _substring_type_error_result(self, invalid_type, state)
        if string_slice_bounds_are_definitely_invalid(args[2:]):
            return _slice_type_error_result(self.qualname, state)
        exact = _exact_find_result(args, reverse=False)
        if exact is not None:
            if exact == -1:
                return ModelResult.none(
                    side_effects=SideEffects.value_error(self.qualname, "substring not found"),
                )
            return ModelResult(value=SymbolicValue.from_const(exact))
        original = SymbolicString.resolve(args[0]) if args else None
        substring = SymbolicString.resolve(args[1]) if len(args) > 1 else None
        side_effects: dict[str, object] = {}
        if original is not None and substring is not None:
            idx = z3.IndexOf(original.z3_str, substring.z3_str, Z3_ZERO)
            result = SymbolicValue(
                _name=f"index_{state.pc}",
                z3_int=idx,
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
            )
            side_effects["potential_exception"] = {
                "type": "ValueError",
                "condition": idx == -1,
                "message": "substring not found",
            }
            constraints = [
                idx >= 0,
                idx < original.z3_len,
                idx + substring.z3_len <= original.z3_len,
            ]
            return ModelResult(
                value=result,
                constraints=constraints,
                side_effects=side_effects,
            )
        result, constraints = ModelResult.symbolic_int(f"index_{state.pc}")
        constraints.append(result.z3_int >= 0)
        return ModelResult(
            value=result,
            constraints=constraints,
        )


class StrRfindModel(FunctionModel):
    """Model for str.rfind() - like find but searches from right.
    Returns -1 if not found, else index in [0, len-1].
    """

    name = "rfind"
    qualname = "str.rfind"

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
            return _substring_type_error_result(self, invalid_type, state)
        if string_slice_bounds_are_definitely_invalid(args[2:]):
            return _slice_type_error_result(self.qualname, state)
        exact = _exact_find_result(args, reverse=True)
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        original = SymbolicString.resolve(args[0]) if args else None
        substring = SymbolicString.resolve(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicValue.symbolic_int(f"rfind_{state.pc}")
        constraints = [constraint, result.z3_int >= -1]
        if original is not None:
            substring_literal = SymbolicString.concrete_literal(args[1]) if len(args) > 1 else None
            if substring_literal == "" and len(args) == 2:
                constraints.append(result.z3_int == original.z3_len)
            else:
                constraints.append(result.z3_int < original.z3_len)
                constraints.append(z3.Implies(original.z3_len == 0, result.z3_int == -1))
                if substring is not None:
                    has_substring = z3.Contains(original.z3_str, substring.z3_str)
                    constraints.append(z3.Implies(has_substring, result.z3_int >= 0))
                    constraints.append(z3.Implies(z3.Not(has_substring), result.z3_int == -1))
                    if len(args) == 2:
                        constraints.append(
                            z3.Implies(
                                result.z3_int == -1,
                                z3.Not(z3.SuffixOf(substring.z3_str, original.z3_str)),
                            ),
                        )
                    constraints.append(
                        z3.Implies(
                            result.z3_int >= 0,
                            result.z3_int + substring.z3_len <= original.z3_len,
                        ),
                    )
        return ModelResult(value=result, constraints=constraints)


class StrRindexModel(FunctionModel):
    """Model for str.rindex() - like rfind but raises ValueError if not found."""

    name = "rindex"
    qualname = "str.rindex"

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
            return _substring_type_error_result(self, invalid_type, state)
        if string_slice_bounds_are_definitely_invalid(args[2:]):
            return _slice_type_error_result(self.qualname, state)
        exact = _exact_find_result(args, reverse=True)
        if exact is not None:
            if exact == -1:
                return ModelResult.none(
                    side_effects=SideEffects.value_error(self.qualname, "substring not found"),
                )
            return ModelResult(value=SymbolicValue.from_const(exact))
        original = SymbolicString.resolve(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic_int(f"rindex_{state.pc}")
        constraints = [constraint, result.z3_int >= 0]
        side_effects: dict[str, object] = {
            "potential_exception": {
                "type": "ValueError",
                "condition": z3.Bool(f"rindex_missing_{state.pc}"),
                "message": "substring not found",
            },
        }
        if original is not None:
            constraints.append(result.z3_int < original.z3_len)
        return ModelResult(value=result, constraints=constraints, side_effects=side_effects)


def _substring_type_error_result(
    model: FunctionModel,
    invalid_type: str,
    state: VMState,
) -> ModelResult:
    return ModelResult.method_type_error(
        model.qualname,
        state,
        message=f"{model.name}() argument 1 must be str, not {invalid_type}",
    )


def _slice_type_error_result(qualname: str, state: VMState) -> ModelResult:
    return ModelResult.method_type_error(
        qualname,
        state,
        message=_SLICE_INDEX_TYPE_ERROR,
    )


def _exact_find_result(args: list[StackValue], *, reverse: bool) -> int | None:
    original = SymbolicString.concrete_literal(args[0])
    substring = SymbolicString.concrete_literal(args[1]) if len(args) > 1 else None
    slice_args = concrete_string_slice_args(args[2:])
    if original is None or substring is None or slice_args is None:
        return None
    return original.rfind(substring, *slice_args) if reverse else original.find(substring, *slice_args)
