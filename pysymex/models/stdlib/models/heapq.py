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

"""Symbolic models for the heapq module."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins import FunctionModel, ModelResult
from pysymex.models.builtins.base import none_model_result
from pysymex.models.containers.lists.shared import get_symbolic_list

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


class HeappushModel(FunctionModel):
    """Model heap length growth for ``heapq.heappush``.

    Heap ordering is intentionally not modeled here; empty-state reasoning only
    requires precise length and mutation tracking.
    """

    name = "heappush"
    qualname = "heapq.heappush"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        heap = get_symbolic_list(args[0], state) if args else None
        side_effects: dict[str, object] = {}
        if heap is not None and len(args) > 1:
            value = (
                args[1] if isinstance(args[1], SymbolicValue) else SymbolicValue.from_const(args[1])
            )
            side_effects["list_mutation"] = {
                "operation": "heappush",
                "original_list": heap,
                "updated_list": heap.append(value),
            }
        return ModelResult(value=SymbolicNone(), side_effects=side_effects)


class HeappopModel(FunctionModel):
    """Model empty-state failure and removal for ``heapq.heappop``."""

    name = "heappop"
    qualname = "heapq.heappop"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"heappop_{state.pc}")
        constraints = [constraint]
        side_effects: dict[str, object] = {}
        heap = get_symbolic_list(args[0], state) if args else None
        if heap is not None:
            constraints.append(heap.z3_len > 0)
            side_effects["potential_exception"] = {
                "type": "IndexError",
                "message": "index out of range",
                "condition": heap.z3_len == 0,
            }
            side_effects["list_mutation"] = {
                "operation": "heappop",
                "original_list": heap,
                "updated_list": heap.__delitem__(0),
            }
        return ModelResult(
            value=result,
            constraints=constraints,
            side_effects=side_effects,
        )


class HeapifyModel(FunctionModel):
    """Model for heapq.heapify()."""

    name = "heapify"
    qualname = "heapq.heapify"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        return none_model_result({"mutates_arg": 0})


class HeapreplaceModel(FunctionModel):
    """Model for heapq.heapreplace()."""

    name = "heapreplace"
    qualname = "heapq.heapreplace"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"heapreplace_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            side_effects={"mutates_arg": 0},
        )


class HeappushpopModel(FunctionModel):
    """Model for heapq.heappushpop()."""

    name = "heappushpop"
    qualname = "heapq.heappushpop"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"heappushpop_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            side_effects={"mutates_arg": 0},
        )


class NlargestModel(FunctionModel):
    """Model for heapq.nlargest()."""

    name = "nlargest"
    qualname = "heapq.nlargest"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"nlargest_{state.pc}")
        if args and isinstance(args[0], int):
            return ModelResult(
                value=result,
                constraints=[constraint, result.z3_len == args[0]],
            )
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class NsmallestModel(FunctionModel):
    """Model for heapq.nsmallest()."""

    name = "nsmallest"
    qualname = "heapq.nsmallest"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"nsmallest_{state.pc}")
        if args and isinstance(args[0], int):
            return ModelResult(
                value=result,
                constraints=[constraint, result.z3_len == args[0]],
            )
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


heapq_models = [
    HeappushModel(),
    HeappopModel(),
    HeapifyModel(),
    HeapreplaceModel(),
    HeappushpopModel(),
    NlargestModel(),
    NsmallestModel(),
]


__all__ = [
    "HeapifyModel",
    "HeappopModel",
    "HeappushModel",
    "HeappushpopModel",
    "HeapreplaceModel",
    "NlargestModel",
    "NsmallestModel",
    "heapq_models",
]
