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

"""Queue models with explicit concurrency and capacity contracts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelDegradation, ModelResult, SideEffects
from pysymex._internal.models.stdlib.coercion import symbolic_int_range, symbolic_object

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def _queue_unknown(method: str) -> ModelDegradation:
    return ModelDegradation(
        kind="unknown",
        label=f"queue.Queue.{method}",
        owner="QueueMethodModel",
        reason="queue contents depend on concurrent scheduling",
    )


class QueueConstructorModel(FunctionModel):
    aliases = ("queue.LifoQueue", "queue.PriorityQueue", "queue.SimpleQueue")
    name = "Queue"
    qualname = "queue.Queue"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        value, constraint = symbolic_object(f"queue_{state.pc}", "queue.Queue")
        maxsize = args[0] if args else kwargs.get("maxsize", 0)
        if not isinstance(maxsize, (int, SymbolicValue)):
            return ModelResult(
                value=value,
                constraints=[constraint],
                side_effects=SideEffects.type_error(self.qualname, "maxsize must be an integer"),
            )
        return ModelResult(
            value=value,
            constraints=[constraint],
            side_effects={"concurrency": True},
        )


class QueueMethodModel(FunctionModel):
    aliases: tuple[str, ...] = ()

    def __init__(self, method: Literal["put", "get", "qsize", "empty", "full"]) -> None:
        self.name = f"queue_Queue_{method}"
        self.qualname = f"queue.Queue.{method}"
        self._method = method

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if self._method == "put":
            if not args:
                return ModelResult.none(SideEffects.type_error(self.qualname, "put() missing item"))
            return ModelResult.none({"concurrency": True, "mutates_arg": 0})
        if self._method == "get":
            value, constraint = SymbolicValue.symbolic(f"queue_get_{state.pc}")
            return ModelResult(
                value=value,
                constraints=[constraint],
                side_effects={"concurrency": True, "mutates_arg": 0},
                degradations=[_queue_unknown(self._method)],
            )
        if self._method == "qsize":
            result = symbolic_int_range(f"queue_size_{state.pc}", 0, None)
            return ModelResult(
                value=result.value,
                constraints=result.constraints,
                degradations=[_queue_unknown(self._method)],
            )
        value, constraint = SymbolicValue.symbolic_bool(f"queue_{self._method}_{state.pc}")
        return ModelResult(
            value=value,
            constraints=[constraint],
            degradations=[_queue_unknown(self._method)],
        )


queue_models: list[FunctionModel] = [
    QueueConstructorModel(),
    *(QueueMethodModel(method) for method in ("put", "get", "qsize", "empty", "full")),
]
