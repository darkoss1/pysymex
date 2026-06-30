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

"""Symbolic models for the bisect module."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def _concrete_int_items(lst: SymbolicList) -> list[int] | None:
    items = lst.concrete_items
    if items is None:
        return None
    values: list[int] = []
    for item in items:
        concrete = item.value if isinstance(item, SymbolicValue) else item
        if not isinstance(concrete, int) or isinstance(concrete, bool):
            return None
        values.append(concrete)
    return values


def _bisect_position(values: list[int], needle: SymbolicValue, *, right: bool) -> z3.ArithRef:
    position: z3.ArithRef = ConstraintValues.int(len(values))
    for index, item in reversed(list(enumerate(values))):
        comparison = needle.z3_int < item if right else needle.z3_int <= item
        position = z3.If(comparison, ConstraintValues.int(index), position)
    return position


def _bisect_index_result(
    prefix: str,
    args: list[StackValue],
    state: VMState,
    *,
    right: bool,
) -> ModelResult:
    result, constraint = SymbolicValue.symbolic_int(f"{prefix}_{state.pc}")
    constraints = [constraint, result.z3_int >= 0]
    lst = SymbolicList.resolve(args[0], state) if args else None
    if lst is not None:
        constraints.append(result.z3_int <= lst.z3_len)
        needle = args[1] if len(args) > 1 and isinstance(args[1], SymbolicValue) else None
        values = _concrete_int_items(lst)
        if values is not None and needle is not None:
            constraints.append(result.z3_int == _bisect_position(values, needle, right=right))
    return ModelResult(value=result, constraints=constraints)


class BisectLeftModel(FunctionModel):
    """Model for bisect.bisect_left()."""

    name = "bisect_left"
    qualname = "bisect.bisect_left"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return _bisect_index_result("bisect_left", args, state, right=False)


class BisectRightModel(FunctionModel):
    """Model for bisect.bisect_right()."""

    name = "bisect_right"
    qualname = "bisect.bisect_right"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return _bisect_index_result("bisect_right", args, state, right=True)


class BisectModel(FunctionModel):
    """Model for bisect.bisect() (alias for bisect_right)."""

    name = "bisect"
    qualname = "bisect.bisect"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return _bisect_index_result("bisect", args, state, right=True)


class InsortLeftModel(FunctionModel):
    """Model for bisect.insort_left()."""

    name = "insort_left"
    qualname = "bisect.insort_left"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return ModelResult.none({"mutates_arg": 0})


class InsortRightModel(FunctionModel):
    """Model for bisect.insort_right()."""

    name = "insort_right"
    qualname = "bisect.insort_right"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return ModelResult.none({"mutates_arg": 0})


class InsortModel(FunctionModel):
    """Model for bisect.insort() (alias for insort_right)."""

    name = "insort"
    qualname = "bisect.insort"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return ModelResult.none({"mutates_arg": 0})


bisect_models = [
    BisectLeftModel(),
    BisectRightModel(),
    BisectModel(),
    InsortLeftModel(),
    InsortRightModel(),
    InsortModel(),
]
