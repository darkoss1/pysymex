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
    SymbolicValue,
    concrete_string_literal,
    get_symbolic_string,
    method_type_error_result,
    symbolic_int_result,
    z3,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

"""Index-style symbolic string search models."""


class StrFindModel(FunctionModel):
    """Model for str.find() - uses Z3 IndexOf with proper bounds.
    Relationships:
    - Returns -1 if not found
    - Returns index >= 0 and < len(s) if found
    - Index + len(sub) <= len(s)
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
            return method_type_error_result(self.qualname, state)
        exact = _exact_find_result(args, reverse=False)
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        original = get_symbolic_string(args[0]) if args else None
        substring = get_symbolic_string(args[1]) if len(args) > 1 else None
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
        result, constraints = symbolic_int_result(f"find_{state.pc}")
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
            return method_type_error_result(self.qualname, state)
        exact = _exact_find_result(args, reverse=False)
        if exact is not None:
            side_effects = _value_error_side_effect(exact, "substring not found in str.index()")
            return ModelResult(value=SymbolicValue.from_const(exact), side_effects=side_effects)
        original = get_symbolic_string(args[0]) if args else None
        substring = get_symbolic_string(args[1]) if len(args) > 1 else None
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
                "message": "substring not found in str.index()",
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
        result, constraints = symbolic_int_result(f"index_{state.pc}")
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
            return method_type_error_result(self.qualname, state)
        exact = _exact_find_result(args, reverse=True)
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        original = get_symbolic_string(args[0]) if args else None
        substring = get_symbolic_string(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicValue.symbolic(f"rfind_{state.pc}")
        constraints = [constraint, result.is_int, result.z3_int >= -1]
        if original is not None:
            substring_literal = concrete_string_literal(args[1]) if len(args) > 1 else None
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
                            )
                        )
                    constraints.append(
                        z3.Implies(
                            result.z3_int >= 0,
                            result.z3_int + substring.z3_len <= original.z3_len,
                        )
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
            return method_type_error_result(self.qualname, state)
        exact = _exact_find_result(args, reverse=True)
        if exact is not None:
            side_effects = _value_error_side_effect(exact, "substring not found")
            return ModelResult(value=SymbolicValue.from_const(exact), side_effects=side_effects)
        original = get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"rindex_{state.pc}")
        constraints = [constraint, result.is_int, result.z3_int >= 0]
        side_effects: dict[str, object] = {
            "potential_exception": {
                "type": "ValueError",
                "condition": z3.Bool(f"rindex_missing_{state.pc}"),
                "message": "substring not found",
            }
        }
        if original is not None:
            constraints.append(result.z3_int < original.z3_len)
        return ModelResult(value=result, constraints=constraints, side_effects=side_effects)


__all__ = ["StrFindModel", "StrIndexModel", "StrRfindModel", "StrRindexModel"]


def _exact_find_result(args: list[StackValue], *, reverse: bool) -> int | None:
    original = concrete_string_literal(args[0])
    substring = concrete_string_literal(args[1]) if len(args) > 1 else None
    slice_args = _exact_slice_args(args[2:])
    if original is None or substring is None or slice_args is None:
        return None
    return (
        original.rfind(substring, *slice_args) if reverse else original.find(substring, *slice_args)
    )


def _value_error_side_effect(result: int, message: str) -> dict[str, object]:
    if result != -1:
        return {}
    return {
        "potential_exception": {
            "type": "ValueError",
            "condition": Z3_TRUE,
            "message": message,
        }
    }


def _exact_slice_args(args: list[StackValue]) -> list[int | None] | None:
    slice_args: list[int | None] = []
    for value in args:
        supported, concrete_index = _concrete_optional_int(value)
        if not supported:
            return None
        slice_args.append(concrete_index)
    return slice_args


def _concrete_optional_int(value: object) -> tuple[bool, int | None]:
    if isinstance(value, SymbolicValue):
        value = value.value
    if value is None:
        return True, None
    if isinstance(value, bool):
        return True, int(value)
    if isinstance(value, int):
        return True, value
    return False, None
