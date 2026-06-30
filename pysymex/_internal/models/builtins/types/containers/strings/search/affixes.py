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

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.string_search import (
    concrete_optional_string_index,
    concrete_string_index,
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

"""Replace and affix symbolic string search models."""

_SLICE_INDEX_TYPE_ERROR = "slice indices must be integers or None or have an __index__ method"


class StrReplaceModel(FunctionModel):
    """Model for str.replace() - result length relationship.
    Relationships:
    - If old and new have same length: result length == original length
    - If old is longer: result length <= original length
    - If new is longer: result length >= original length.
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
            return ModelResult.method_type_error(self.qualname, state)
        old_invalid_type = string_type_name_if_definitely_not_string(args[1])
        if old_invalid_type is not None:
            return ModelResult.method_type_error(
                self.qualname,
                state,
                message=f"replace() argument 1 must be str, not {old_invalid_type}",
            )
        new_invalid_type = string_type_name_if_definitely_not_string(args[2])
        if new_invalid_type is not None:
            return ModelResult.method_type_error(
                self.qualname,
                state,
                message=f"replace() argument 2 must be str, not {new_invalid_type}",
            )
        if len(args) > 3:
            count_error = _definite_invalid_count_error(args[3])
            if count_error is not None:
                return ModelResult.method_type_error(self.qualname, state, message=count_error)
        original = SymbolicString.resolve(args[0]) if args else None
        old_str = SymbolicString.resolve(args[1]) if len(args) > 1 else None
        new_str = SymbolicString.resolve(args[2]) if len(args) > 2 else None
        exact = _exact_replace_result(args)
        if exact is not None:
            return ModelResult(value=SymbolicString.from_const(exact))

        count = concrete_string_index(args[3]) if len(args) > 3 else -1
        if count == 0 and original is not None:
            return ModelResult(value=original)

        old_literal = SymbolicString.concrete_literal(args[1]) if len(args) > 1 else None
        if (
            count == 1
            and original is not None
            and old_str is not None
            and new_str is not None
            and old_literal not in {None, ""}
        ):
            replaced = z3.Replace(original.z3_str, old_str.z3_str, new_str.z3_str)
            return ModelResult(
                value=SymbolicString(
                    _z3_str=replaced,
                    _z3_len=z3.Length(replaced),
                    _name=f"replace_{state.pc}",
                ),
            )

        result, base_constraint = SymbolicString.symbolic(f"replace_{state.pc}")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len >= 0)
            if old_str is not None:
                old_not_found = z3.Not(z3.Contains(original.z3_str, old_str.z3_str))
                constraints.append(z3.Implies(old_not_found, result.z3_len == original.z3_len))
                constraints.append(z3.Implies(old_not_found, result.z3_str == original.z3_str))
            if old_str is not None and new_str is not None:
                old_len = SymbolicString.concrete_literal(args[1])
                new_len = SymbolicString.concrete_literal(args[2])
                if old_len is not None and new_len is not None and len(old_len) == len(new_len):
                    constraints.append(result.z3_len == original.z3_len)
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
            return ModelResult.method_type_error(self.qualname, state)
        operand_error = _affix_operand_type_error(self.name, args[1])
        if operand_error is not None:
            return ModelResult.method_type_error(self.qualname, state, message=operand_error)
        if string_slice_bounds_are_definitely_invalid(args[2:]):
            return ModelResult.method_type_error(
                self.qualname,
                state,
                message=_SLICE_INDEX_TYPE_ERROR,
            )
        exact = _exact_affix_result(args, suffix=False)
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        original = SymbolicString.resolve(args[0]) if args else None
        prefix = SymbolicString.resolve(args[1]) if len(args) > 1 else None
        if len(args) > 2:
            return ModelResult.bool(f"startswith_{state.pc}")
        if original is not None and prefix is not None:
            result_bool = z3.PrefixOf(prefix.z3_str, original.z3_str)
            result = SymbolicValue(
                _name=f"startswith_{state.pc}",
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=result_bool,
                is_bool=Z3_TRUE,
                affinity_type="bool",
            )
            return ModelResult(value=result, constraints=[])
        return ModelResult.bool(f"startswith_{state.pc}")


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
            return ModelResult.method_type_error(self.qualname, state)
        operand_error = _affix_operand_type_error(self.name, args[1])
        if operand_error is not None:
            return ModelResult.method_type_error(self.qualname, state, message=operand_error)
        if string_slice_bounds_are_definitely_invalid(args[2:]):
            return ModelResult.method_type_error(
                self.qualname,
                state,
                message=_SLICE_INDEX_TYPE_ERROR,
            )
        exact = _exact_affix_result(args, suffix=True)
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        original = SymbolicString.resolve(args[0]) if args else None
        suffix = SymbolicString.resolve(args[1]) if len(args) > 1 else None
        if len(args) > 2:
            return ModelResult.bool(f"endswith_{state.pc}")
        if original is not None and suffix is not None:
            result_bool = z3.SuffixOf(suffix.z3_str, original.z3_str)
            result = SymbolicValue(
                _name=f"endswith_{state.pc}",
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=result_bool,
                is_bool=Z3_TRUE,
                affinity_type="bool",
            )
            return ModelResult(value=result, constraints=[])
        return ModelResult.bool(f"endswith_{state.pc}")


def _affix_operand_type_error(method: str, value: object) -> str | None:
    if SymbolicString.resolve(value) is not None:
        return None
    tuple_items = _tuple_affix_items(value)
    if tuple_items is not None:
        for item in tuple_items:
            invalid_type = string_type_name_if_definitely_not_string(item)
            if invalid_type is not None:
                return f"tuple for {method} must only contain str, not {invalid_type}"
        return None
    invalid_type = string_type_name_if_definitely_not_string(value)
    if invalid_type is None:
        return None
    return f"{method} first arg must be str or a tuple of str, not {invalid_type}"


def _definite_invalid_count_error(value: object) -> str | None:
    if isinstance(value, SymbolicValue):
        if z3.is_true(value.is_none):
            return "'NoneType' object cannot be interpreted as an integer"
        if value.value is None:
            return None
        value = value.value
    if isinstance(value, SymbolicNoneType) or value is None:
        return "'NoneType' object cannot be interpreted as an integer"
    if isinstance(value, bool | int):
        return None
    type_name = "str" if SymbolicString.resolve(value) is not None else type(value).__name__
    return f"'{type_name}' object cannot be interpreted as an integer"


def _exact_affix_operand(value: object) -> str | tuple[str, ...] | None:
    literal = SymbolicString.concrete_literal(value)
    if literal is not None:
        return literal
    tuple_items = _tuple_affix_items(value)
    if tuple_items is None:
        return None
    literals: list[str] = []
    for item in tuple_items:
        item_literal = SymbolicString.concrete_literal(item)
        if item_literal is None:
            return None
        literals.append(item_literal)
    return tuple(literals)


def _tuple_affix_items(value: object) -> tuple[object, ...] | None:
    if isinstance(value, tuple):
        return cast("tuple[object, ...]", value)
    if isinstance(value, SymbolicList) and getattr(value, "_type", None) == "tuple":
        items = value.concrete_items
        if items is None:
            return None
        return tuple(items)
    return None


def _exact_affix_result(args: list[StackValue], *, suffix: bool) -> bool | None:
    source = SymbolicString.concrete_literal(args[0])
    affix = _exact_affix_operand(args[1]) if len(args) > 1 else None
    if source is None or affix is None:
        return None

    slice_args: list[int | None] = []
    for value in args[2:]:
        supported, concrete_index = concrete_optional_string_index(value)
        if not supported:
            return None
        slice_args.append(concrete_index)

    if suffix:
        return source.endswith(affix, *slice_args)
    return source.startswith(affix, *slice_args)


def _exact_replace_result(args: list[StackValue]) -> str | None:
    original = SymbolicString.concrete_literal(args[0])
    old = SymbolicString.concrete_literal(args[1]) if len(args) > 1 else None
    new = SymbolicString.concrete_literal(args[2]) if len(args) > 2 else None
    if original is None or old is None or new is None:
        return None
    count = concrete_string_index(args[3]) if len(args) > 3 else -1
    if count is None:
        return None
    return original.replace(old, new, count)
