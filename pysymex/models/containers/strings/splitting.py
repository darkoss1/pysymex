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

from pysymex.core.constants import Z3_TRUE
from pysymex.models.builtins.core.iterator_items import concrete_iterable_items

from .shared import (
    FunctionModel,
    ModelResult,
    SymbolicList,
    SymbolicString,
    SymbolicValue,
    concrete_string_literal,
    get_symbolic_string,
    method_type_error_result,
    z3,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

"""Split, join, and partition symbolic string models."""


class StrSplitModel(FunctionModel):
    """Model for str.split() - relationship between parts and original.
    Relationships:
    - len(s.split()) >= 1 (always at least one element)
        - For explicit non-empty separator:
            - separator not found => len(s.split(sep)) == 1
            - separator found => len(s.split(sep)) >= 2
    - Each element length <= original length
    """

    name = "split"
    qualname = "str.split"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if (
            len(args) not in {1, 2, 3}
            or set(kwargs) - {"sep", "maxsplit"}
            or (len(args) > 1 and "sep" in kwargs)
            or (len(args) > 2 and "maxsplit" in kwargs)
        ):
            return method_type_error_result(self.qualname, state)
        original = get_symbolic_string(args[0]) if args else None
        sep_arg = args[1] if len(args) > 1 else kwargs.get("sep")
        maxsplit_arg = args[2] if len(args) > 2 else kwargs.get("maxsplit")
        separator = get_symbolic_string(sep_arg) if sep_arg is not None else None
        exact = _exact_split_result(args[0], sep_arg, maxsplit_arg, reverse=False)
        if exact is not None:
            return ModelResult(value=exact)
        result, base_constraint = SymbolicList.symbolic(f"split_{state.pc}")
        constraints = [
            base_constraint,
            result.z3_len >= 1,
        ]
        if original is not None:
            constraints.append(result.z3_len <= original.z3_len + 1)
            if separator is not None:
                sep_non_empty = separator.z3_len > 0
                has_sep = z3.Contains(original.z3_str, separator.z3_str)
                constraints.append(
                    z3.Implies(z3.And(sep_non_empty, z3.Not(has_sep)), result.z3_len == 1)
                )
                constraints.append(z3.Implies(z3.And(sep_non_empty, has_sep), result.z3_len >= 2))
        return ModelResult(value=result, constraints=constraints)


class StrJoinModel(FunctionModel):
    """Model for str.join() - result length based on separator and parts.
    Relationship: If joining N parts with separator S:
    - len(result) >= sum of part lengths
    - len(result) includes (N-1) * len(S) for separators
    """

    name = "join"
    qualname = "str.join"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return method_type_error_result(self.qualname, state)
        exact = _exact_join_result(args[0], args[1], state)
        if exact is not None:
            return exact
        result, base_constraint = SymbolicString.symbolic(f"join_{state.pc}")
        constraints = [base_constraint]
        constraints.append(result.z3_len >= 0)
        return ModelResult(value=result, constraints=constraints)


class StrRsplitModel(FunctionModel):
    """Model for str.rsplit() - like split but from right."""

    name = "rsplit"
    qualname = "str.rsplit"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if (
            len(args) not in {1, 2, 3}
            or set(kwargs) - {"sep", "maxsplit"}
            or (len(args) > 1 and "sep" in kwargs)
            or (len(args) > 2 and "maxsplit" in kwargs)
        ):
            return method_type_error_result(self.qualname, state)
        original = get_symbolic_string(args[0]) if args else None
        sep_arg = args[1] if len(args) > 1 else kwargs.get("sep")
        maxsplit_arg = args[2] if len(args) > 2 else kwargs.get("maxsplit")
        exact = _exact_split_result(args[0], sep_arg, maxsplit_arg, reverse=True)
        if exact is not None:
            return ModelResult(value=exact)
        result, base_constraint = SymbolicList.symbolic(f"rsplit_{state.pc}")
        constraints = [base_constraint, result.z3_len >= 1]
        if original is not None:
            constraints.append(result.z3_len <= original.z3_len + 1)
        return ModelResult(value=result, constraints=constraints)


def _exact_split_result(
    original_arg: StackValue,
    sep_arg: StackValue | None,
    maxsplit_arg: StackValue | None,
    *,
    reverse: bool,
) -> SymbolicList | None:
    original = concrete_string_literal(original_arg)
    if original is None:
        return None
    sep = None if sep_arg is None else concrete_string_literal(sep_arg)
    if sep_arg is not None and sep is None:
        return None
    if sep == "":
        return None
    maxsplit = _concrete_int(maxsplit_arg) if maxsplit_arg is not None else -1
    if maxsplit is None:
        return None
    parts = original.rsplit(sep, maxsplit) if reverse else original.split(sep, maxsplit)
    return SymbolicList.from_const(parts)


def _concrete_int(value: object) -> int | None:
    if isinstance(value, SymbolicValue):
        value = value.value
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return None


def _exact_join_result(
    separator_arg: StackValue,
    iterable_arg: StackValue,
    state: VMState,
) -> ModelResult | None:
    separator = concrete_string_literal(separator_arg)
    if separator is None:
        return None
    items = concrete_iterable_items(iterable_arg, state)
    if items is None:
        return None
    parts: list[str] = []
    for item in items:
        part = concrete_string_literal(item)
        if part is None:
            if _definitely_not_string(item):
                return method_type_error_result("str.join", state)
            return None
        parts.append(part)
    return ModelResult(value=SymbolicString.from_const(separator.join(parts)))


def _definitely_not_string(value: object) -> bool:
    if concrete_string_literal(value) is not None:
        return False
    if isinstance(value, SymbolicValue):
        return value.value is not None
    if isinstance(value, SymbolicString):
        return False
    return True


class StrPartitionModel(FunctionModel):
    """Model for str.partition(sep) - returns (before, sep, after) 3-tuple."""

    name = "partition"
    qualname = "str.partition"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return method_type_error_result(self.qualname, state)
        exact, is_exact = _exact_partition_result(args[0], args[1], reverse=False)
        if is_exact:
            if exact is None:
                return _value_error_result("partition", "empty separator", state)
            return ModelResult(value=SymbolicList.from_const(list(exact)))
        result, constraint = SymbolicList.symbolic(f"partition_{state.pc}")
        constraints = [constraint, result.z3_len == 3]
        return ModelResult(value=result, constraints=constraints)


class StrRpartitionModel(FunctionModel):
    """Model for str.rpartition(sep) - like partition but from right."""

    name = "rpartition"
    qualname = "str.rpartition"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return method_type_error_result(self.qualname, state)
        exact, is_exact = _exact_partition_result(args[0], args[1], reverse=True)
        if is_exact:
            if exact is None:
                return _value_error_result("rpartition", "empty separator", state)
            return ModelResult(value=SymbolicList.from_const(list(exact)))
        result, constraint = SymbolicList.symbolic(f"rpartition_{state.pc}")
        constraints = [constraint, result.z3_len == 3]
        return ModelResult(value=result, constraints=constraints)


class StrSplitlinesModel(FunctionModel):
    """Model for str.splitlines() - splits on line boundaries."""

    name = "splitlines"
    qualname = "str.splitlines"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if (
            len(args) not in {1, 2}
            or set(kwargs) - {"keepends"}
            or (len(args) > 1 and "keepends" in kwargs)
        ):
            return method_type_error_result(self.qualname, state)
        keepends_arg = args[1] if len(args) > 1 else kwargs.get("keepends")
        exact = _exact_splitlines_result(args[0], keepends_arg)
        if exact is not None:
            return ModelResult(value=exact)
        original = get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicList.symbolic(f"splitlines_{state.pc}")
        constraints = [base_constraint, result.z3_len >= 0]
        if original is not None:
            constraints.append(result.z3_len <= original.z3_len)
            constraints.append(z3.Implies(original.z3_len == 0, result.z3_len == 0))
        return ModelResult(value=result, constraints=constraints)


def _exact_partition_result(
    source_arg: StackValue,
    sep_arg: StackValue,
    *,
    reverse: bool,
) -> tuple[tuple[str, str, str] | None, bool]:
    source = concrete_string_literal(source_arg)
    sep = concrete_string_literal(sep_arg)
    if source is None or sep is None:
        return None, False
    if sep == "":
        return None, True
    parts = source.rpartition(sep) if reverse else source.partition(sep)
    return parts, True


def _exact_splitlines_result(
    source_arg: StackValue,
    keepends_arg: StackValue | None,
) -> SymbolicList | None:
    source = concrete_string_literal(source_arg)
    if source is None:
        return None
    keepends = _concrete_truth(keepends_arg) if keepends_arg is not None else False
    if keepends is None:
        return None
    return SymbolicList.from_const(source.splitlines(keepends))


def _concrete_truth(value: object) -> bool | None:
    if isinstance(value, SymbolicValue):
        value = value.value
    if value is None:
        return False
    if isinstance(value, (bool, int, str, bytes)):
        return bool(value)
    return None


def _value_error_result(name: str, message: str, state: VMState) -> ModelResult:
    result, constraint = SymbolicList.symbolic(f"{name}_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects={
            "potential_exception": {
                "type": "ValueError",
                "condition": Z3_TRUE,
                "message": message,
            }
        },
    )
